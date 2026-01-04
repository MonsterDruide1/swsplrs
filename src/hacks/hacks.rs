pub trait Hacks {
    fn get_jump_tables(&self) -> Vec<(u64, usize)>;
    fn get_object_path(&self, object_name: &str) -> String;
}
