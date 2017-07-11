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
		
		let mut suffix: String = String::from("<RCRMETA-FORMAT: |");
		suffix.push_str(&self.format.clone());
		suffix.push_str("| >");
		self.content.extend(suffix.into_bytes().iter().cloned());
		
		for i in 0..self.content.len() {
			let key_c: u8 = key_chars[i % key_chars.len()] as u8;
			let x: u32 = ((self.content[i] as u32) + key_c as u32) as u32;
			let enc_c: u8 = (x % 256) as u8;
			
			enc.push(enc_c);
		}
		
		self.format = String::from("rcr");
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
		
		//interpret format
		let mut i = dec.len()-1;
		let mut buffering = false;
		let mut buf: Vec<u8> = Vec::new();
		let mut format_built = false;
		while i != 0 {
			let ch = match dec.pop() {
				Some(x) => x,
				None => break,
			};
			if ch == ('>' as u8) {
				buffering = true;
			} else if buffering && ch == ('<' as u8) {
				buffering = false;
				format_built = true;
			}
			
			buf.push(ch);
			
			if !buffering { 
				break;
			}
			i -= 1;
		}
		
		if format_built {
			buf.reverse();
			let meta: String = String::from_utf8(buf).expect("Cannot build string");
			let f_ar: Vec<String> = meta.split("|").map(|s| s.to_string()).collect();
			let f: String = f_ar.get(1).expect("Out of bounds").clone();
			self.format = f;
		} else {
			self.format = String::from("");
		}
		
		
		self.content = dec;
	}
	
	pub fn save_as(&self, name: &String) {
		let mut n2 = name.clone();
		n2.push_str(".");
		n2.push_str(&self.format);
		let path = Path::new(&n2);
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
		
		if cf.format == "rcr" {
			cf.decrypt(&password);
			let mut name: String = String::from("temp/");
			name.push_str(&cf.name.clone());
			cf.save_as(&name);
		} else {
			cf.encrypt(&password);
			let name: String = cf.name.clone();
			cf.save_as(&name);
		}
		
	}
}
