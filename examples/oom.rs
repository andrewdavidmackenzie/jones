fn foo() -> usize {
    63
}

fn main() {
    vec![0; 1 << foo()];
}
