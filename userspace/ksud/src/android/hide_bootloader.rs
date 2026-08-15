use std::path::Path;

use const_format::concatcp;
use log::{info, warn};

use crate::defs::WORKING_DIR;

use super::resetprop;

const HIDE_BOOTLOADER_CONFIG: &str = concatcp!(WORKING_DIR, ".hide_bootloader");

// properties to reset for hiding bootloader unlock status
const PROPS_TO_HIDE: &[(&str, &str)] = &[
    ("ro.boot.vbmeta.device_state", "locked"),
    ("ro.boot.verifiedbootstate", "green"),
    ("ro.boot.flash.locked", "1"),
    ("ro.boot.veritymode", "enforcing"),
    ("ro.boot.warranty_bit", "0"),
    ("ro.warranty_bit", "0"),
    ("ro.debuggable", "0"),
    ("ro.force.debuggable", "0"),
    ("ro.secure", "1"),
    ("ro.adb.secure", "1"),
    ("ro.build.type", "user"),
    ("ro.build.tags", "release-keys"),
    ("ro.vendor.boot.warranty_bit", "0"),
    ("ro.vendor.warranty_bit", "0"),
    ("vendor.boot.vbmeta.device_state", "locked"),
    ("vendor.boot.verifiedbootstate", "green"),
    ("sys.oem_unlock_allowed", "0"),
    ("ro.secureboot.lockstate", "locked"),
    ("ro.boot.realmebootstate", "green"),
    ("ro.boot.realme.lockstate", "1"),
    ("ro.boot.oem_unlock_support", "0"),
];

pub fn is_hide_bootloader_enabled() -> bool {
    Path::new(HIDE_BOOTLOADER_CONFIG).exists()
}

fn check_reset_prop(name: &str, expected: &str) {
    let value = match resetprop::get_property_direct(name) {
        Ok(Some(value)) => value,
        _ => return, // property does not exist
    };
    if value == expected {
        return;
    }
    if let Err(err) = resetprop::set_property_direct(name, expected) {
        warn!("hide bootloader: failed to set {name}: {err}");
    } else {
        info!("hide bootloader: {name} {value} -> {expected}");
    }
}

pub fn hide_bootloader_status() {
    if !is_hide_bootloader_enabled() {
        return;
    }

    info!("hide bootloader: enabled");
    for (name, expected) in PROPS_TO_HIDE {
        check_reset_prop(name, expected);
    }
}
