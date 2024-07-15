

use litcrypt::{self, lc};
use litcrypt::use_litcrypt;
use std::{ffi::CString, os::raw::{c_char, c_int}};


// string obfuscation
// If this is raising an error ensure
// env var LITCRYPT_ENCRYPT_KEY is set
// hash from: dd if=/dev/urandom bs=4096 count=1 | shasum
use_litcrypt!("48b0ef7d6bdf408b66a3a986403ca6f69e3287de");




mod tests;


#[cfg(target_os = "macos")]
mod mac;

#[cfg(target_os = "windows")]
mod win;

#[cfg(target_os = "linux")]
mod lin;




use std::ptr;

#[no_mangle]
pub extern "C" fn simple_machine_id(buffer: *mut c_char, buffer_size: *mut c_int) -> c_int {

    let mid = machine_id();
    //println!("rs/ ret[{}]", mid);

    let c_string = CString::new(mid).expect("CString::new failed");
    let c_string_bytes = c_string.as_bytes_with_nul();
    let required_size = c_string_bytes.len() as c_int;

    if buffer.is_null() || buffer_size.is_null() {
        return -1; // Invalid arguments
    }

    unsafe {
        // Dereference buffer_size to get the value it points to
        let buf_size = *buffer_size;

        if buf_size < required_size {
            // Update buffer_size with the required size
            *buffer_size = required_size;
            return -2; // Buffer too small
        }

        // Copy CString to the provided buffer
        ptr::copy_nonoverlapping(c_string_bytes.as_ptr(), buffer as *mut u8, required_size as usize);
        *buffer_size = required_size; //update with number of bytes returned.
    }

    0 // Success
}






pub fn machine_id() -> String{
    
    //check flag file..
    if machine_id_dev_mode() {
        let m_str = lc!("machine_id_dev_mode_123");
        let rx: i32 = 4;//rand::random();
        return format!("{}{rx}", m_str);

    }else{

        #[cfg(target_os = "windows")]
        return win::machine_id();
        
        #[cfg(target_os = "macos")]
        return mac::machine_id();

        #[cfg(target_os = "linux")]
        return lin::machine_id();

        // if there's no machine type handler the code wont even compile.
        //panic!("Invalid machine type.");
        
    }

}




// check a flag file to see if the lib should return a hard coded machine id
fn machine_id_dev_mode() -> bool{


    return false; // wrap this in a compile option flag or something

    /*
    //let filename = crate::filenames::machine_id_dev_mode();
    let filename = "/tmp/machine_id-rs.txt"; //FIXME: 
    
    match std::fs::File::open(filename){
        Ok(fh) => {
            let dev_mode_msg = lc!("*** Machine ID is in dev mode. ***");
            print!("{}", dev_mode_msg);
            //xplm::debugln!("{}", dev_mode_msg);
            drop(fh);

            return true;
        },
        Err(_e) => {

            // debugln!("  DID NOT find an auto update flag file on disk..");
            return false;
        }
    } //can we find a file?
    */

}

