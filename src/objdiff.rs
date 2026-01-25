use std::path::PathBuf;

use objdiff_core::config::{save_project_config, ProjectConfig, ProjectConfigInfo, ProjectObject};

use crate::{file_list::Object, hacks::hacks::Hacks};

pub fn write_config(path: PathBuf, file_list: &Vec<(String, Object)>, hacks: &dyn Hacks) -> anyhow::Result<()> {
    // TODO: read all config options everywhere and configure "properly"
    let units = file_list.iter().map(|(name, obj)| {
        let path = hacks.get_object_path(name);
        let mappings = obj.text_section.iter()
                .filter(|s| s.guess)
                .map(|s| (format!("loc_{:X}", s.offset), s.name().to_string()))
                .collect();
        ProjectObject {
            name: Some(path.clone()),
            target_path: Some(format!("out/split/obj/{}", path).into()),
            base_path: Some(format!("build/CMakeFiles/odyssey.dir/{}", path.replace(".o", ".cpp.obj")).into()),
            symbol_mappings: Some(mappings),
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
