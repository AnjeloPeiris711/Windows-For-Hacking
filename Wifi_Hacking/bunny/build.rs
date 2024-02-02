extern crate cc;

fn main() {
    cc::Build::new().file("src/lib/test.c").compile("test");
}