

use registry::{Hive, Security};




pub fn machine_id() -> String{

    read_registry_entries()

}



fn read_registry_entries() -> String{

    // we collect all our bytes into one large vector.
    let mut blob_vec: Vec<u8> = vec!();


    // Open Cryptography Hive
    let regkey = Hive::LocalMachine.open(r"SOFTWARE\Microsoft\Cryptography", Security::Read).expect("Could not open crypto hive.");

    let machine_guid = regkey.value(r"MachineGuid").unwrap();
    let tstring = machine_guid.to_string();
    let tv = tstring.as_bytes();
    //println!("machine guid: {}", tv.len()+1);
    blob_vec.extend_from_slice(tv);
    blob_vec.extend_from_slice(b"\0:");



    // Open Current Version Hive
    let regkey = Hive::LocalMachine.open(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", Security::Read).expect("Could not open version hive.");

    //Binary
    let digital_product_id = regkey.value(r"DigitalProductId").unwrap();
    let mut tv: Vec<u8> = digital_product_id.to_bytes();
    //println!("prod id: {}", tv.len());
    blob_vec.append( &mut tv );
    blob_vec.extend_from_slice(b":");

    //Binary
    let digital_product_id4 = regkey.value(r"DigitalProductId4").unwrap();
    let mut tv: Vec<u8> = digital_product_id4.to_bytes();
    //println!("prod id4: {}", tv.len());
    blob_vec.append( &mut tv );
    blob_vec.extend_from_slice(b":");



    // --------

    // * 
    
    
    // Using these can be problematic as the Insiders Program and Windows Update process have a habit of updating the values.
    /*
    //DWORD
    let install_date = regkey.value(r"InstallDate").unwrap();
    let mut tv: Vec<u8> = install_date.to_bytes();
    println!("install date: {}", tv.len());
    blob_vec.append( &mut tv );
    blob_vec.extend_from_slice(b":");

    //DWORD
    let install_time = regkey.value(r"InstallTime").unwrap();
    let mut tv: Vec<u8> = install_time.to_bytes();
    println!("install time: {}", tv.len());
    blob_vec.append( &mut tv );
    blob_vec.extend_from_slice(b":");

    let current_build = regkey.value(r"CurrentBuild").unwrap();
    let tstring = current_build.to_string();
    let tv = tstring.as_bytes();
    println!("current build: {}", tv.len()+1);
    blob_vec.extend_from_slice(tv);
    blob_vec.extend_from_slice(b"\0:");
    */



    let edition_id = regkey.value(r"EditionID").unwrap();
    let tstring = edition_id.to_string();
    let tv = tstring.as_bytes();
    println!("edition id: {}", tv.len()+1);
    blob_vec.extend_from_slice(tv);
    blob_vec.extend_from_slice(b"\0:");

    let path_name = regkey.value(r"PathName").unwrap();
    let tstring = path_name.to_string();
    let tv = tstring.as_bytes();
    println!("path name: {}", tv.len()+1);
    blob_vec.extend_from_slice(tv);
    blob_vec.extend_from_slice(b"\0:");

    let product_id = regkey.value(r"ProductId").unwrap();
    let tstring = product_id.to_string();
    let tv = tstring.as_bytes();
    println!("product id: {}", tv.len()+1);
    blob_vec.extend_from_slice(tv);
    blob_vec.extend_from_slice(b"\0:");

    let product_name = regkey.value(r"ProductName").unwrap();
    let tstring = product_name.to_string();
    let tv = tstring.as_bytes();
    println!("product name: {}", tv.len()+1);
    blob_vec.extend_from_slice(tv);
    blob_vec.extend_from_slice(b"\0:");


    //let registered_orginization = regkey.value(r"RegisteredOrginization").unwrap(); //legacy typo?
    //let registered_orginization = regkey.value(r"RegisteredOrganization").unwrap(); //correct
    let registered_orginization: Vec<u8> = vec!(0; 2048);
    let mut tv: Vec<u8> = registered_orginization; //.to_bytes();
    println!("org: {}", tv.len());
    blob_vec.append( &mut tv );
    blob_vec.extend_from_slice(b":");


    let registered_owner = regkey.value(r"RegisteredOwner").unwrap();
    let tstring = registered_owner.to_string();
    let tv = tstring.as_bytes();
    println!("registered owner: {}", tv.len()+1);
    blob_vec.extend_from_slice(tv);
    blob_vec.extend_from_slice(b"\0:");

    let release_id = regkey.value(r"ReleaseId").unwrap();
    let tstring = release_id.to_string();
    let tv = tstring.as_bytes();
    println!("release id: {}", tv.len()+1);
    blob_vec.extend_from_slice(tv);
    blob_vec.extend_from_slice(b"\0:");

    // ----
    //blob_vec.truncate( 1024 );
    //println!("blob length: {}", blob_vec.len());
    //println!("{:?}", blob_vec);


    let digest = md5::compute( blob_vec );
    let hash_string = format!("{:x}", digest);
    
    hash_string

}

