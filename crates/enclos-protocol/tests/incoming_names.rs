#[test]
fn canonical_incoming_names() {
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!("fixtures/incoming_names.json")).unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        assert_eq!(enclos_protocol::incoming::check_name(name).is_ok(), case["accepted"].as_bool().unwrap(), "{case}");
    }
}
