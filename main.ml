let fail err msg =
  prerr_endline ("Error: " ^ err);
  print_endline ("Reason: " ^ msg);
  exit 1;;

open Cryptokit;;

let filename = 
  try (Sys.argv.(1))
  with Invalid_argument err -> 
    fail err "Need file argument" in

let direction = 
  try
    match (Sys.argv.(2)) with
      "encrypt" -> Cipher.Encrypt
    | "decrypt" -> Cipher.Decrypt
    | _ -> fail "Need direction argument" 
                "Argument 2 can be either 'encrypt' or 'decrypt'";
  with Invalid_argument err -> 
    fail err "Argument 2 can be either 'encrypt' or 'decrypt'" in

let key = 
  print_string "Enter key: ";
  flush stdout;
  try input_line stdin
  with End_of_file -> fail "Invalid key" "" in

let in_chan = 
  try open_in (Sys.argv.(1))
  with Sys_error err -> fail err "" in

let outfilename = 
  if direction == Cipher.Encrypt 
  then (filename ^ ".enc")
  else ((String.sub filename 0 ((String.length filename)-4)) ^ ".dec") in


let keyhash = 
  let h = Hash.sha256 () in
  h#add_string key;
  h#result in

let transform = Cipher.aes ~mode:Cipher.CBC ~pad:Padding._8000 keyhash direction in
try
  while true do
    transform#put_byte (input_byte in_chan)
  done
with End_of_file -> ();

transform#finish;
close_in in_chan;
print_endline ("Transformed " ^ (string_of_int transform#available_output) ^ " bytes");

let out_chan = 
  open_out outfilename in

try
  while true do
    output_byte out_chan transform#get_byte 
  done
with End_of_file -> ();

transform#wipe;
close_out out_chan;
print_endline ("Saved to file '" ^ outfilename ^ "'");
