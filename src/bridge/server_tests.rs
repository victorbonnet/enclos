use super::*;

fn out(file: &str) -> OutAttachment {
    OutAttachment {
        file: file.to_owned(),
        mime: "image/png".to_owned(),
        name: "folder/unicorn.png".to_owned(),
        size: 4,
    }
}

#[test]
fn a_file_of_the_media_folder_is_moved_into_the_bridges() {
    let dir = tempfile::tempdir().unwrap();
    let (inbox, media) = (dir.path().join("media"), dir.path().join("app-media"));
    std::fs::create_dir(&inbox).unwrap();
    std::fs::write(inbox.join("a1.png"), b"\x89PNG").unwrap();
    let taken = take_attachment(&inbox, &media, "c-1", &out("a1.png")).unwrap();
    assert_eq!(
        (taken.size, taken.name.as_str(), taken.mime.as_str()),
        (4, "unicorn.png", "image/png")
    );
    assert_eq!(std::fs::read(media.join(&taken.id)).unwrap(), b"\x89PNG");
    assert!(!inbox.join("a1.png").exists(), "moved, not copied");
}

#[test]
fn a_link_a_path_or_a_folder_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (inbox, media) = (dir.path().join("media"), dir.path().join("app-media"));
    std::fs::create_dir(&inbox).unwrap();
    std::fs::write(dir.path().join("secret"), b"host file").unwrap();
    std::os::unix::fs::symlink(dir.path().join("secret"), inbox.join("link.png")).unwrap();
    std::fs::create_dir(inbox.join("folder")).unwrap();
    for file in [
        "link.png",
        "../secret",
        "/etc/hosts",
        ".hidden",
        "folder",
        "",
    ] {
        assert!(
            take_attachment(&inbox, &media, "c-1", &out(file)).is_err(),
            "{file:?}"
        );
    }
    assert_eq!(
        std::fs::read(dir.path().join("secret")).unwrap(),
        b"host file"
    );
}

#[test]
fn a_strange_media_type_is_a_plain_file() {
    let dir = tempfile::tempdir().unwrap();
    let (inbox, media) = (dir.path().join("media"), dir.path().join("app-media"));
    std::fs::create_dir(&inbox).unwrap();
    std::fs::write(inbox.join("a2.bin"), b"x").unwrap();
    let mut a = out("a2.bin");
    a.mime = "text/html; <script>".to_owned();
    assert_eq!(
        take_attachment(&inbox, &media, "c-1", &a).unwrap().mime,
        "application/octet-stream"
    );
}
