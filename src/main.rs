use clap::{App, Arg};
use hyper::{HeaderMap, Response};
use hyper::body::Bytes;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Cursor, Write, ErrorKind};
use std::path::Path;
use gotham::pipeline::set::{new_pipeline_set, finalize_pipeline_set};
use gotham::pipeline::new_pipeline;
use gotham::middleware::session::NewSessionMiddleware;
use gotham::router::builder::{build_router, DrawRoutes, DefineSingleRoute};
use gotham::rustls;
use gotham::rustls::NoClientAuth;
use gotham::rustls::internal::pemfile::{certs, pkcs8_private_keys};

use gotham::state::{FromState, State};
use std::pin::Pin;
use gotham::handler::HandlerFuture;
use gotham::hyper::{body, Body, Uri, StatusCode};
use gotham::helpers::http::response::{create_response, create_empty_response};
use mime::{TEXT_HTML, IMAGE_JPEG, IMAGE_PNG, IMAGE_SVG, TEXT_CSS, TEXT_JAVASCRIPT, TEXT_XML, TEXT_PLAIN, Mime};
use std::fs;
use serde::{Deserialize, Serialize};
use futures_util::{future, FutureExt};
use multipart::server::{Multipart, MultipartField};
use gotham::hyper::header::CONTENT_TYPE;
use serde_json::json;

fn process_multipart(cookie_value: String, m: &mut Multipart<Cursor<Bytes>>) -> Vec<String> {
    // Create the base directory path based on the cookie
    let base_dir = format!("/Volumes/lucas_disk1/photo_unload/images/{}", cookie_value);

    // Check if the directory exists, create it if not
    if let Err(e) = fs::create_dir_all(&base_dir) {
        if e.kind() != ErrorKind::AlreadyExists {
            println!("Directory already exists");
        }
    }

    let mut live_photos = HashMap::new();
    let mut videos = Vec::new();

    let mut failed_images = Vec::new();

    m.foreach_entry(|mut field: MultipartField<&mut Multipart<Cursor<Bytes>>>| {
        
        let content_type = field.headers.content_type.as_ref().expect("No content type provided").to_string();
        println!("content_type: {}", content_type);

        let filename = field.headers.filename.unwrap();
        let mut data = Vec::new();
        field.data.read_to_end(&mut data).expect("Can't read");

        if data.is_empty() {
            println!("FILE IS EMPTY!: {filename:?}");
            failed_images.push(filename);
        } else if filename.to_lowercase().ends_with(".heic") || filename.to_lowercase().ends_with(".mov") {
            // Handle Live Photos
            // You can use the filename (minus the extension) as the key
            let key = filename.split('.').next().unwrap().to_string();
            live_photos.entry(key).or_insert(Vec::new()).push((filename, data));
        } else if filename.to_lowercase().ends_with(".mp4") || filename.to_lowercase().ends_with(".avi") || filename.to_lowercase().ends_with(".mkv") {
            // Handle video files
            videos.push((filename, data));
        }else {
            // Generate the path where the image or video will be saved
            let image_path = format!("{}/{}", base_dir, filename);
            println!("image_path: {}", image_path);
            // Open a new file and write the image data to it
            match File::create(Path::new(&image_path)) {
                Ok(mut file) => {
                    file.write_all(&data).expect("Couldn't write data to file");
                },
                Err(e) => {
                    println!("Error creating file: {:?} for image_path: {}", e, image_path);
                }
            };
        }
        

    }).expect("An error occurred while reading multipart entries");

    let live_keys = live_photos.keys();
    println!("Hashmap: {live_keys:?}");

    // Save the Live Photos
    for (key, files) in live_photos.iter() {
        // Create a directory for each Live Photo based on the key
        let live_photo_dir = format!("{}/{}", base_dir, key);
        if let Err(e) = fs::create_dir_all(&live_photo_dir) {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                println!("Failed to create directory: {}", live_photo_dir);
                continue;
            }
        }

        // Save the .HEIC and .MOV files in the directory
        for (filename, data) in files.iter() {
            let file_path = format!("{}/{}", live_photo_dir, filename);
            match File::create(Path::new(&file_path)) {
                Ok(mut file) => {
                    file.write_all(data).expect("Couldn't write data to file");
                },
                Err(e) => {
                    println!("Error creating file: {:?} for file_path: {}", e, file_path);
                }
            };
        }
    }

    // Save the video files
    for (filename, data) in videos.iter() {
        let video_path = format!("{}/{}", base_dir, filename);
        match File::create(Path::new(&video_path)) {
            Ok(mut file) => {
                file.write_all(data).expect("Couldn't write data to file");
            },
            Err(e) => {
                println!("Error creating file: {:?} for video_path: {}", e, video_path);
            }
        };
    }

    failed_images

}



fn upload_handler_single(mut state: State) -> (State, Response<Body>) {
    println!("arrived into handler");
    let response = create_empty_response(&state, StatusCode::OK);
    return (state, response)

    /*let header_map = gotham::hyper::HeaderMap::take_from(&mut state);
    let content_type = header_map.get(CONTENT_TYPE).unwrap().to_str().unwrap();

    if !content_type.starts_with("image/") {
        let response = create_empty_response(&state, StatusCode::BAD_REQUEST);
        return (state, response);
    }

    let response = create_empty_response(&state, StatusCode::OK);
    (state, response)*/
}

fn upload_handler(mut state: State) -> Pin<Box<HandlerFuture>> {
    const BOUNDARY: &str = "boundary=";
    let header_map = HeaderMap::take_from(&mut state);
    let boundary = header_map
        .get(CONTENT_TYPE)
        .and_then(|ct| {
            let ct = ct.to_str().ok()?;
            let idx = ct.find(BOUNDARY)?;
            Some(ct[idx + BOUNDARY.len()..].to_string())
        })
        .unwrap();
    
    // Extract and parse cookie from header to build the file's directory
    let cookie = header_map.get("cookie").unwrap().to_str().unwrap();
    let mut cookie = cookie.split_once("user_uuid=").unwrap().1.to_string();
    if cookie.contains(';') {
        cookie = cookie.split_once(',').unwrap().0.to_string()
    }

    body::to_bytes(Body::take_from(&mut state))
        .then(|full_body| match full_body {
            Ok(valid_body) => {
                let mut m = Multipart::with_body(Cursor::new(valid_body), boundary);
                let error_files = process_multipart(cookie, &mut m);
                let error_files_json = json!({ "error_files": error_files }).to_string();
                let res = create_response(&state, StatusCode::OK, TEXT_HTML, error_files_json);
                future::ok((state, res)) 
            }
            Err(e) => future::err((state, e.into())),
        })
        .boxed()
}


fn get_main(mut state: State) -> Pin<Box<HandlerFuture>> {
    let f = body::to_bytes(Body::take_from(&mut state)).then(|full_body| match full_body {
        Ok(valid_body) => {

            let _ = String::from_utf8(valid_body.to_vec()).unwrap();
            let uri = Uri::borrow_from(&state).to_string();

            // If we receive additional arguments in the URI we can handle them
            let uri_elements = uri.split("&").collect::<Vec<&str>>();
            println!("Uri main got {} arguments: {:?}", uri_elements.len(), uri_elements);

            let body_content = fs::read_to_string("photo_unloader/index.html").unwrap();
            let mut res = create_response(&state, StatusCode::OK, TEXT_HTML, body_content);
            future::ok((state, res))

        }
        Err(e) => future::err((state, e.into())),
    });
    f.boxed()
}


fn to_dir_handler(mut state: State) -> Pin<Box<HandlerFuture>> {
    let f = body::to_bytes(Body::take_from(&mut state)).then(|full_body| match full_body {
        Ok(valid_body) => {
            let _ = String::from_utf8(valid_body.to_vec()).unwrap();
            let uri = Uri::borrow_from(&state).to_string();

            // If we receive additional arguments in the URI we can handle them
            let uri_elements = uri.split("&").collect::<Vec<&str>>();
            println!("Uri handler got {:?}", uri_elements);
            let file_location = format!{"photo_unloader/{}", uri_elements[0]}.replace("[\"", "").replace("\"]", "").replacen("/", "", 1);

            let file_extension = &file_location.split("/").collect::<Vec<&str>>();
            let file_extension = file_extension.last().unwrap().to_owned();
            let (_, file_extension) = match file_extension.split_once(".") {
                Some((anterior, file_extension)) => (anterior, file_extension),
                _ => {("error", "error")}
            };

            let mime_type = match file_extension {
                "jpg" => { IMAGE_JPEG}
                "jpeg" => { IMAGE_JPEG}
                "png" => {IMAGE_PNG}
                "svg" => {IMAGE_SVG}
                "html" => { TEXT_HTML}
                "css" => { TEXT_CSS}
                "js" => {TEXT_JAVASCRIPT}
                "xml" => {TEXT_XML}
                _ => {
                    //println!("file location is {}, anterior is {} and file extension is {}", file_location, anterior, file_extension);
                    TEXT_PLAIN
                }
            };


            println!("file location: {}", &file_location);
            let body_content = match File::open(&file_location) {
                Ok(mut body) => {
                    let mut file_content = Vec::new();
                    match body.read_to_end(&mut file_content) {
                        Ok(_) => file_content,
                        _ => {
                            println!("error reading at {}", file_location);
                            format!("error reading").as_bytes().to_vec()
                        }
                    }
                }
                Err(_) => {
                    let mut body = format!("error");
                    //println!("error get support {:?} for {}", e, file_location);
                    let mut file_content = Vec::new();
                    file_content
                }
            };
            let mut res = create_response(&state, StatusCode::OK, mime_type, body_content);
            future::ok((state, res))

        }
        Err(e) => future::err((state, e.into())),
    });
    f.boxed()
}


#[derive(Clone, Deserialize, Serialize)]
pub struct UserData {
    pub(crate) user_id: String,
    pub(crate) connected: bool,
    last_interaction: String
}

impl UserData {
    fn new() -> Self {
        Self {
            user_id: uuid::Uuid::nil().to_string(),
            connected: true,
            last_interaction: "".to_string()
        }
    }
}

fn main() {
    let cmd: clap::ArgMatches = parse_cmd();
    let addr: String = cmd.value_of("ip").unwrap_or_default().to_string();

    let middleware = match cmd.is_present("https") {
        true => {
            // If Https is enabled, create a secure middleware handling LoginData over sessions
            NewSessionMiddleware::default().with_session_type::<Option<UserData>>()
        }
        false => {
            NewSessionMiddleware::default()
                // Configure the type of data which we want to store in the session.
                // See the custom_data_type example for storing more complex data.
                .with_session_type::<Option<UserData>>()
                // By default, the cookies used are only sent over secure connections. For our test server,
                // we don't set up an HTTPS certificate, so we allow the cookies to be sent over insecure
                // connections. This should not be done in real applications.
                .insecure()
        }
    };

    let pipelines = new_pipeline_set();

    let (pipelines, default) = pipelines.add(
        new_pipeline()
            .add(middleware)
            .build(),
    );

    let pipeline_set = finalize_pipeline_set(pipelines);
    let default_chain = (default, ());
    //let extended_chain = (extended, default_chain);
   // let extended_chain = (extended2, extended_chain);
    println!("Listening for requests at https://{}", addr);

    let router = build_router(default_chain, pipeline_set, |route| {

        route.scope("/", |route| {
            route.get("").to(get_main);
        });

        route.post("/upload").to(upload_handler);

        route.get("/*").to(to_dir_handler);
    });

    if cmd.is_present("https") {
        // TLS gotham server that load the .pem files
        gotham::start_with_tls(addr, router, build_config().unwrap());
    } else {
        // Gotham HTTP
        gotham::start(addr, router);
    }

}


// Load the certificates
fn build_config() -> Result<rustls::ServerConfig, rustls::TLSError> {
    let mut cfg = rustls::ServerConfig::new(NoClientAuth::new());
    let full_chain = File::open("your cert").unwrap();
    let mut cert_file = BufReader::new(full_chain);
    let priv_key = File::open("your key").unwrap();
    let mut key_file = BufReader::new(priv_key);
    let certs = certs(&mut cert_file).unwrap();

    let mut keys = pkcs8_private_keys(&mut key_file).unwrap();

    cfg.set_single_cert(certs, keys.remove(0))?;
    Ok(cfg)
}

pub fn parse_cmd() -> clap::ArgMatches<'static> {
    let matches = App::new("")
        .arg(Arg::with_name("ip")
            .short("ip")
            .long("ip")
            .value_name("String")
            .help("Bind to tihs [ip:port] of your server")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("https")
            .short("https")
            .long("https")
            .help("Run with https enabled"))
        .arg(Arg::with_name("origin")
            .short("origin")
            .long("origin")
            .help("Specifies Access-Control-Allow-Origin")
            .required(true)
            .takes_value(true))
        .get_matches();

    println!("{:?}", matches);

    return matches;
}

