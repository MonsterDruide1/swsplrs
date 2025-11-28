pub trait Hacks {
    fn get_jump_tables(&self) -> Vec<(u64, usize)>;
}
