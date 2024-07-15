use md5;


pub fn machine_id() -> String{

    let machine_id_raw = machine_id_raw();

    let digest = md5::compute(machine_id_raw.as_bytes());
    let hash_string = format!("{:x}", digest);
    
    hash_string

}




fn machine_id_raw() -> String{
    "lol_linux".to_string()
}