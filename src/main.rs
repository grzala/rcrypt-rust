use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::io;
use std::env;

struct CipherFile {
	content: Vec<u8>,
	name: String,
	format: String,
}

impl CipherFile {
	pub fn new(path_str: String) -> CipherFile {
		let path = Path::new(&path_str);
		let mut file = match File::open(path) {
			Err(why) => panic!("couldn't open {}: {}", path.display(), why.description()),
			Ok(file) => file,
		};
		
		let mut s: Vec<u8> = Vec::new();
		s = match file.read_to_end(&mut s) {
			Err(why) => panic!("couldn't read {}: {}", path.display(), why.description()),
			Ok(_) => s,
		};
		
		let mut f: Vec<String> = path_str.split(".").map(|s| s.to_string()).collect();
		let ref f2 = f.pop().expect("name empty");
		CipherFile {
			content: s,
			format: f2.clone(),
			name: f.join("").clone(),
		}
	}
	
	fn encrypt(&mut self, key: &String) {
		let mut enc: Vec<u8> = Vec::new();
		let key_chars: Vec<char> = key.chars().collect();
		for i in 0..self.content.len() {
			let key_c: u8 = key_chars[i % key_chars.len()] as u8;
			let x: u32 = ((self.content[i] as u32) + key_c as u32) as u32;
			let enc_c: u8 = (x % 256) as u8;
			
			enc.push(enc_c);
		}
		
		self.content = enc;
	}
	
	pub fn decrypt(&mut self, key: &String) {
		let mut dec: Vec<u8> = Vec::new();
		let key_chars: Vec<char> = key.chars().collect();
		for i in 0..self.content.len() {
			let key_c = key_chars[i % key_chars.len()] as u32;
			let x: u32 = 256 + (self.content[i] as u32) - key_c;
			let dec_c = (x % 256) as u8;
			
			dec.push(dec_c);
		}
		
		self.content = dec;
	}
	
	pub fn save_as(&self, name: &String) {
		let path = Path::new(&name);
		let mut f = File::create(&path).expect("Unable to create file");
		f.write_all(&self.content).expect("Unable to write data");
	}
}


fn main() {
	println!("Type password: ");
    let mut password = String::new();
    io::stdin().read_line(&mut password).expect("Failed to read line");
    
    let args: Vec<_> = env::args().collect();
    for i in 1..args.len() {
		let arg = args.get(i).expect("Args out of index").clone();
		let mut cf = CipherFile::new(arg);
		println!("CRYPT: {}, FORMAT: {}", cf.name, cf.format);
		
		cf.encrypt(&password);
		let mut name1: String = cf.name.clone();
		name1.push_str(".rcr");
		cf.save_as(&name1);
		
		cf.decrypt(&password);
		let mut name2: String = "temp/".to_string();
		name2.push_str(&cf.name.clone());
		name2.push_str(".");
		name2.push_str(&cf.format.clone());
		cf.save_as(&name2);
	}
}
