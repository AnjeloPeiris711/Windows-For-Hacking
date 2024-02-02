extern crate core;
use core::ffi::c_int;



extern "C" {
    // fn multiply(a: c_int, b: c_int) -> c_int;
    fn test() -> c_int;

}

pub fn packet_dump() {
    unsafe {
        // let argc = 2;
        // let argv = vec![b"./test.pcap\0".as_ptr() as *mut c_char].as_mut_ptr();
        let result = test();

        println!("[Rust] Result: {}", result);

        
    }
}
 pub fn packet_dump_save(){
    panic!("not implement");
 }
    

















    




