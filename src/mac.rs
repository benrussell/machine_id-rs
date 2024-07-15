extern crate IOKit_sys;
extern crate CoreFoundation_sys as cf;
extern crate libc;
extern crate mach;

use std::ffi::{CString,CStr};

use libc::{ c_char,
            //c_void
            };

use litcrypt::lc;
use IOKit_sys::*;
use cf::*;

use md5;







pub fn machine_id() -> String{

    let uuid_query_key: String = lc!("IOPlatformUUID");
    let platform_uuid = io_registry_query(&uuid_query_key).unwrap();

    
    let ret: String;

    let hackintosh_uuid: String = lc!("55ADE930-5FDF-5EC4-8429-15640684C489");    
    if hackintosh_uuid == platform_uuid {
        // if its a hackintosh we add the serial number.
        //println!("This is a hackintosh..");
        let serial_query_key: String = lc!("IOPlatformSerialNumber");
        let platform_serial = io_registry_query(&serial_query_key).unwrap();

        ret = format!("{}//{}", platform_uuid, platform_serial);
        drop(platform_serial);
        drop(platform_uuid);
    
    }else{
        //println!("This is NOT a hackintosh.");
        //println!("raw serial: {}", platform_serial);;
        ret = platform_uuid;
    }
    //println!("apple mid raw: {}", ret);

    let mut vec_hash_input = ret.as_bytes().to_vec();
    vec_hash_input.append( vec!(0; 1024 - ret.len() ).as_mut() );
    drop(ret);
    //println!("total vec len: {}", vec_hash_input.len());
    //println!("{:?}", vec_hash_input );

    let digest = md5::compute(vec_hash_input);
    let hash_string = format!("{:x}", digest);
    
    hash_string
}




fn io_registry_query( key_name: &str ) -> Result<String,String>{

    unsafe{
        let io_service_query_key: String = lc!("IOService:/");
        let io_service_path = CString::new(io_service_query_key.as_bytes().to_vec()).unwrap();
        let io_registry_root = IORegistryEntryFromPath(kIOMasterPortDefault, io_service_path.as_ptr() );
        drop(io_service_query_key);
        drop(io_service_path);

        let c_key_name = CString::new(key_name).unwrap();
        let cf_lookup_str = CFStringCreateWithCStringNoCopy(
                                                                std::ptr::null(), 
                                                                c_key_name.as_ptr(), 
                                                                kCFStringEncodingMacRoman, 
                                                                std::ptr::null()
                                                            );

        let cf_prop = IORegistryEntryCreateCFProperty(io_registry_root, cf_lookup_str, kCFAllocatorDefault, 0);

        const BUFF_SIZE: usize = 1024;
        let mut buf = Vec::<c_char>::with_capacity(BUFF_SIZE);

        CFStringGetCString(cf_prop as CFStringRef, buf.as_mut_ptr(), BUFF_SIZE as i64, kCFStringEncodingMacRoman);
        CFRelease(cf_prop);

        IOObjectRelease(io_registry_root);

        match CStr::from_ptr(buf.as_ptr()).to_str(){
            Ok(s) => Ok(s.to_string()),
            Err(e) => Err(e.to_string()),
        }

    }

}

