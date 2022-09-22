use cantracer::is_pie;
use std::fs::{read, write};
use std::path::PathBuf;
use std::process::Command;
const TEST_CODE: &str = r#"
#include <stdio.h>
#include <stdlib.h>

void listen() {
    char buf[1024];
    unsigned long i = 0;
    while (i < sizeof(buf) - 1) {
        buf[i] = getchar();
        if (buf[i] == '\n') {
            buf[i] = '\0';
            break;
        }
        i++;
    }
    printf("%s", buf);
}

int main(void) {
    listen();
    return 0;
}
"#;
#[test]
fn test_gettext() -> Result<(), Box<dyn std::error::Error>> {
    let CARGO_TARGET_TMPDIR: PathBuf = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let TEST_CODE_FILE: PathBuf = CARGO_TARGET_TMPDIR.join("test.c");
    let TEST_BIN_FILE: PathBuf = CARGO_TARGET_TMPDIR.join("test");
    let TEST_PIC_BIN_FILE: PathBuf = CARGO_TARGET_TMPDIR.join("test-pic");

    write(CARGO_TARGET_TMPDIR.join("test.c"), TEST_CODE).expect("Failed to write test code");

    Command::new("gcc")
        .arg("-o")
        .arg(&TEST_BIN_FILE)
        .arg(&TEST_CODE_FILE)
        .output()
        .expect("Failed to compile test code");

    Command::new("gcc")
        .arg("-fPIC")
        .arg("-pie")
        .arg("-o")
        .arg(&TEST_PIC_BIN_FILE)
        .arg(&TEST_CODE_FILE)
        .output()
        .expect("Failed to compile test code");

    assert!(
        is_pie(TEST_PIC_BIN_FILE),
        "PIE binary is not detected as PIE"
    );
    assert!(!is_pie(TEST_BIN_FILE), "no-PIE binary is detected as PIE");

    Ok(())
}
