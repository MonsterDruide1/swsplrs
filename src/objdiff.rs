use std::path::PathBuf;

use objdiff_core::config::{save_project_config, ProjectConfig, ProjectConfigInfo, ProjectObject};

use crate::file_list::Object;

pub fn write_config(path: PathBuf, file_list: &Vec<(String, Object)>) -> anyhow::Result<()> {
    // TODO: read all config options everywhere and configure "properly"
    let units = file_list.iter().map(|(name, _)| {
        ProjectObject {
            name: Some(name.clone()),
            target_path: Some(format!("out/split/obj/{}", name).into()),
            base_path: Some(format!("build/CMakeFiles/odyssey.dir/lib/al/{}", name.replace(".o", ".cpp.obj")).into()),
            ..Default::default()
        }
    }).collect();

    let config = ProjectConfig {
        min_version: Some("3.3.0".to_string()),
        build_base: Some(false),
        build_target: Some(false),
        units: Some(units),
        ..Default::default()
    };

    save_project_config(&config, &ProjectConfigInfo {
        path,
        timestamp: None,
    })?;

    Ok(())
}
