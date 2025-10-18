use bip157::{
    BlockHash, Event, IndexedFilter, SyncUpdate, UnboundedReceiver,
    tokio::sync::mpsc::UnboundedSender,
};
use indexer::bdk_chain::BlockId;
use redb::{Database, TableDefinition};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

const QUEUE_SIZE: usize = 999;

pub const TABLE_DEF: TableDefinition<u32, Vec<u8>> = TableDefinition::new("filters");

pub struct WriteRange {
    pub writes: BTreeMap<u32, BlockHash>,
}

#[derive(Debug)]
pub struct DatabaseBuffer {
    queue: BTreeSet<IndexedFilter>,
    db: Arc<Mutex<Database>>,
}

impl DatabaseBuffer {
    pub fn new(db: Arc<Mutex<Database>>) -> Self {
        Self {
            queue: BTreeSet::new(),
            db,
        }
    }

    pub fn write_queue(&mut self) -> WriteRange {
        let write = self.db.lock().unwrap().begin_write().unwrap();
        let mut writes = BTreeMap::new();
        {
            let mut table = write.open_table(TABLE_DEF).unwrap();
            for indexed_filter in core::mem::take(&mut self.queue) {
                writes.insert(indexed_filter.height(), indexed_filter.block_hash());
                table
                    .insert(indexed_filter.height(), indexed_filter.into_contents())
                    .unwrap();
            }
        }
        write.commit().unwrap();
        WriteRange { writes }
    }

    pub fn push_filter(&mut self, filter: IndexedFilter) -> Option<WriteRange> {
        self.queue.insert(filter);
        if self.queue.len() > QUEUE_SIZE {
            return Some(self.write_queue());
        }
        None
    }
}

pub enum FilterEvent {
    Changes(WriteRange),
    Tip(BlockId),
}

#[derive(Debug)]
pub struct FilterSubscriber {
    db_buffer: DatabaseBuffer,
    receiver: UnboundedReceiver<Event>,
    sender: UnboundedSender<FilterEvent>,
    birthday: u32,
}

impl FilterSubscriber {
    pub fn new(
        db_buffer: DatabaseBuffer,
        receiver: UnboundedReceiver<Event>,
        sender: UnboundedSender<FilterEvent>,
        birthday: u32,
    ) -> Self {
        Self {
            db_buffer,
            receiver,
            sender,
            birthday,
        }
    }

    pub async fn run(&mut self) -> Result<(), UpdateError> {
        while let Some(message) = self.receiver.recv().await {
            match message {
                Event::FiltersSynced(SyncUpdate { tip, .. }) => {
                    tracing::info!("Sending new changes to tweak subscriber");
                    let changes = self.db_buffer.write_queue();
                    if self.sender.send(FilterEvent::Changes(changes)).is_err() {
                        return Err(UpdateError::ChannelClosed);
                    }
                    let tip = BlockId {
                        height: tip.height,
                        hash: tip.hash,
                    };
                    self.sender.send(FilterEvent::Tip(tip)).unwrap();
                }
                Event::IndexedFilter(filter) => {
                    if filter.height() < self.birthday {
                        continue;
                    };
                    if let Some(changes) = self.db_buffer.push_filter(filter) {
                        if self.sender.send(FilterEvent::Changes(changes)).is_err() {
                            return Err(UpdateError::ChannelClosed);
                        }
                    }
                }
                _ => {}
            }
        }
        Err(UpdateError::NodeStopped)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum UpdateError {
    NodeStopped,
    ChannelClosed,
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateError::NodeStopped => write!(f, "the node halted execution."),
            UpdateError::ChannelClosed => write!(f, "the updates channel was closed."),
        }
    }
}

impl std::error::Error for UpdateError {}
