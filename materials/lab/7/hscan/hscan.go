package hscan

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	//"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

//==========================================================================\\
//303872
/* 
to do from /x/crypto
	MD4         Hash = 1 + iota // import golang.org/x/crypto/md4
	RIPEMD160                   // import golang.org/x/crypto/ripemd160
	SHA3_224                    // import golang.org/x/crypto/sha3
	SHA3_256                    // import golang.org/x/crypto/sha3
	SHA3_384                    // import golang.org/x/crypto/sha3
	SHA3_512                    // import golang.org/x/crypto/sha3
	BLAKE2s_256                 // import golang.org/x/crypto/blake2s
	BLAKE2b_256                 // import golang.org/x/crypto/blake2b
	BLAKE2b_384                 // import golang.org/x/crypto/blake2b
	BLAKE2b_512                 // import golang.org/x/crypto/blake2b
 */
var shalookup = make(map[string]string)
var md5lookup = make(map[string]string)
var wg sync.WaitGroup
var m5 sync.Mutex 
var s1 sync.Mutex 
var s224 sync.Mutex 
var s256 sync.Mutex 
var s384 sync.Mutex 
var s512 sync.Mutex 

/* 
	MD5                         // import crypto/md5
	SHA1                        // import crypto/sha1
	SHA224                      // import crypto/sha256
	SHA256                      // import crypto/sha256
	SHA384                      // import crypto/sha512
	SHA512                      // import crypto/sha512

	Create the needed .txt files, this is the heavy, slow part
  */
func createMd5(toBeHashed string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(toBeHashed)))

}
func createSHA1(toBeHashed string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(toBeHashed)))
	
}
func createSHA224(toBeHashed string) string {
	return fmt.Sprintf("%x", sha256.Sum224([]byte(toBeHashed)))
	
}
func createSHA256(toBeHashed string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(toBeHashed)))
	
}
func createSHA384(toBeHashed string) string {
	return fmt.Sprintf("%x", sha512.Sum384([]byte(toBeHashed)))
	
}
func createSHA512(toBeHashed string) string {
	return fmt.Sprintf("%x", sha512.Sum512([]byte(toBeHashed)))
	
}
//to control go rutines
func md5Control(pass string, file *os.File){
	mypass := createMd5(pass)
	m5.Lock()
	if _, err := file.WriteString(mypass +"\n"); err != nil {
		panic(err)
	}
	m5.Unlock()
	wg.Done()
}
func sha1Control(pass string, file *os.File){
	mypass := createSHA1(pass)
	m5.Lock()
	if _, err := file.WriteString(mypass +"\n"); err != nil {
		panic(err)
	}
	m5.Unlock()
	wg.Done()

}
func sha224Control(pass string, file *os.File){
	mypass := createSHA224(pass)
	m5.Lock()
	if _, err := file.WriteString(mypass +"\n"); err != nil {
		panic(err)
	}
	m5.Unlock()
	wg.Done()

}
func sha256Control(pass string, file *os.File){
	mypass := createSHA256(pass)
	m5.Lock()
	if _, err := file.WriteString(mypass +"\n"); err != nil {
		panic(err)
	}
	m5.Unlock()
	wg.Done()

}
func sha384Control(pass string, file *os.File){
	mypass := createSHA384(pass)
	m5.Lock()
	if _, err := file.WriteString(mypass +"\n"); err != nil {
		panic(err)
	}
	m5.Unlock()
	wg.Done()

}
func sha512Control(pass string, file *os.File){
	mypass := createSHA512(pass)
	m5.Lock()
	if _, err := file.WriteString(mypass +"\n"); err != nil {
		panic(err)
	}
	m5.Unlock()
	wg.Done()

}
//control structure to create multible
func createHashFiles(filename string, hashes [6]int){
	var filenames [6]*os.File
	//create all mutext locks that might be needed
	//open 'filename'
	f, err := os.Open(filename)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	//creates new files as depending on the number of hashes entered
	var hindex = [7]string{"","md5","sha1","sha224","sha256","sha384","sha512"}
	for i:= 0; i < len(hashes); i++{
		if hashes[i] == 0{
			break
		}
		h,err := os.Create(filename + "-" + hindex[hashes[i]] + ".txt");
		filenames[i] = h
		if err != nil{
			log.Fatal(err)
		}
		defer h.Close()
	}
	//openFiles(hashes)
	//iterate through 'filename' and open a .txt for each hash we will be using
		//naming convention of 'filename'-hash.txt
	for scanner.Scan() {
		password := scanner.Text()
		for i:=0; i< len(hashes); i++{
			if hashes[i] == 0{
				break
			}
			input := hashes[i]
			switch input {
			case 1:
				//write to "md5"
				wg.Add(1)
				go md5Control(password, filenames[i])
			case 2:
				//write to "sha1"
				wg.Add(1)
				go sha1Control(password,filenames[i])
			case 3:
				//write to "sha224" 
				wg.Add(1)
				go sha224Control(password,filenames[i])
			case 4:
				//write to "sha256"
				wg.Add(1)
				go sha256Control(password,filenames[i])
			case 5:
				//write to "sha384"
				wg.Add(1)
				go sha384Control(password,filenames[i])
			case 6:
				//write to "sha512"
				wg.Add(1)
				go sha512Control(password,filenames[i])
			}
		}
	}
	wg.Wait()
	fmt.Println("done with hashing")
}
//used for guessing the type of hash used
func guessHash(hash string) []int{
	//use length of hash to guess the hash
	return make([]int, 0)
}
func guessHashM(fileName string) []int{
	//open file, pull first hash then call guessHash
	return make([]int, 0)
}
func guessSingle(hashedpassword string, hash []int) (string, string){
	var hindex = [6]string{"md5","sha1","sha224","sha256","sha384","sha512"}//to return the name of the hash
	//open needed files from functions
	return "", hindex[1]
}
func guessMultiple(sourcefile string, hash []int) (string, string){
	var hindex = [6]string{"md5","sha1","sha224","sha256","sha384","sha512"}//to return the name of the hash
	return "", hindex[1]
}
/* 
get user input for what hashes should be used. 
 */
func CLI(){
	//fmt.Println()
	//fmt.Scanln(&)
	var input string //where user input will be temp stored
	var filename string//the sourcefile for making the hashfiles

	var functions [6]int//used to create .txt files
	var index = 0 //index to track number of things entered in functions
	var passize string //used to differentiate between a single hash and a file of hashes 
	var passhash string //input from the user to see if they know what type of hash was used
	var fpname string //the hash or file name
	var password string //the found password
	var hashtype string //the found hashtype (un-needed if only one hash was entered in functions)
	fmt.Println("If needed: Help, Options")
	fmt.Println("Do you need to make any .txt files containing hashes? (Y/N)")
	fmt.Scanln(&input)
	for{
		if strings.EqualFold(input, "Y"){
			fmt.Println("what is the name of the .txt you would like to make them from? (full file name)")
			for{
				fmt.Scanln(&input)
				f, err := os.Open(input)
				if err != nil {
					fmt.Println("I'm sorry that file could not be found, try again.")
				}else{
					f.Close()
					break
				}
			}
			filename = input
			fmt.Println("What hash functions would you like to use? (options)")
			for{
				fmt.Scanln(&input)
				if strings.EqualFold(input, "options"){
					fmt.Println("the current supported hash functions are:")
					fmt.Println("1.MD5\n2.SHA1\n3.SHA224\n4.SHA256\n5.SHA384\n6.SHA512")
					fmt.Println("you can use the number associated with the hash or the name of the hash. (all uppercase or all lowercase)")
					fmt.Println("you can enter the same hash more than once, its just wasting your own time.")
					fmt.Println("when you are done selecting just enter \"done\"")
				}else if strings.EqualFold(input,"done"){
					if index == 0 {
						fmt.Print("please enter at least one hash, ")
						break
					}
					break
				}else{
					if(index == 5){
						fmt.Print("you have entered too many hashes, we will just use the ones you have selected.")
						break
					}
					switch input {
						case "1", "MD5", "md5":
							functions[index] = 1
							index++
						case "2","SHA1", "sha1":
							functions[index] = 2
							index++
						case "3", "SHA224", "sha224":
							functions[index] = 3 
							index++
						case "4", "SHA256", "sha256":
							functions[index] = 4
							index++
						case "5", "SAH384", "sha384":
							functions[index] = 5
							index++
						case "6", "SHA512", "sha512":
							functions[index] = 6
							index++
						default: 
							if(index == 0){
								fmt.Println("try again.")
							}else{
								fmt.Println("sorry input not recognized, try again.")
							}
						//where we exit switch
					}
				}
			}
			createHashFiles(filename,functions)
			break
		}else if(strings.EqualFold(input, "N")){
			break
		}else{
			fmt.Println("please enter Y or N")
		}
	}
	fmt.Println("Would you like to check for a single password or multiple through a .txt file? (S/M)")
	for{
		fmt.Scanln(&input)
		if strings.EqualFold(input, "S") || strings.EqualFold(input, "M") {
			passize = input
			fmt.Println("What is the name of the file or what is the hashed password? (don't forget .txt if its a file)")
			fmt.Scanln(&input)
			fpname = input 
			break
		}else{
			fmt.Println("sorry, plese select S/M")
		}
	}
	fmt.Println("do you know the type of hash used? (Y/N)")
	for{
		fmt.Scanln(&input)
		if strings.EqualFold(input, "Y") || strings.EqualFold(input, "N"){
			passhash = input
			break
		}else{
			fmt.Println("sorry, plese select Y/N")
		}
	}
	if strings.EqualFold(passhash, "Y"){
		fmt.Println("What type of hash(s) were used? (options)")
		var hashfunc []int
		for{
			fmt.Scanln(&input)
			if strings.EqualFold(input, "options"){
				fmt.Println("the current supported hash functions are:")
				fmt.Println("1.MD5\n2.SHA1\n3.SHA224\n4.SHA256\n5.SHA384\n6.SHA512")
				fmt.Println("you can use the number associated with the hash or the name of the hash. (all uppercase or all lowercase)")
			}else{
				for{
					switch input {
					case "1", "MD5", "md5":
						hashfunc[0] = 1
						index++
						break
					case "2","SHA1", "sha1":
						hashfunc[0] = 2
						index++
						break
					case "3", "SHA224", "sha224":
						hashfunc[0] = 3
						index++
						break
					case "4", "SHA256", "sha256":
						hashfunc[0] = 4
						index++
						break
					case "5", "SAH384", "sha384":
						hashfunc[0] = 5
						index++
						break
					case "6", "SHA512", "sha512":
						hashfunc[0] = 6
						index++
						break
					default: 
						fmt.Println("sorry input not recognized, try again.")
					}
				}
				//first ask for the sourcefile --------- TODO
				if strings.EqualFold(passize, "S"){
					password, hashtype = guessSingle(fpname, hashfunc)
					password = password 
					hashtype = hashtype 
				}else{//we are dealing with a .txt file of hashes
					password, hashtype = guessMultiple(fpname, hashfunc)
				}
				break
			}
		}
	}else{//N as entered, we need to try to identify the hash(s) used
		//first ask for the sourcefile --------- TODO
		if strings.EqualFold(passize, "S"){
			usedhashes := guessHash(fpname)
			password, hashtype = guessSingle(fpname, usedhashes)
		}else{//we are dealing with a .txt file of hashes
			usedhashes := guessHashM(fpname)
			password, hashtype = guessMultiple(fpname, usedhashes)
		}
	}
} 

/* func GuessSingle(sourceHash string, filename string) string{
	f, err := os.Open(filename)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var ihash = len(sourceHash) == 32
	for scanner.Scan() {
		password := scanner.Text()

		// TODO - From the length of the hash you should know which one of these to check ...
		// add a check and logicial structure
		if ihash{
			hash := fmt.Sprintf("%x", md5.Sum([]byte(password)))
			if hash == sourceHash {
				fmt.Printf("[+] Password found (MD5): %s\n", password)
				return password
			}
		}else{
			hash := fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
			if hash == sourceHash {
				fmt.Printf("[+] Password found (SHA-256): %s\n", password)
				return password
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalln(err)
	}
	return "failure to find password"
} */

/* func md5map(password string, ch chan string){
	ch <- fmt.Sprintf("%x", md5.Sum([]byte(password)))
}
func shamap(password string, ch chan string){
	ch <- fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
} */
/* func GenHashMaps(filename string) {

	f, err := os.Open(filename)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	chmd5 := make(chan string)
	chsha := make(chan string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		password := scanner.Text()
		//var md5lookup map[string]string
		go md5map(password,chmd5)
		//for testing, warning dump
		//fmt.Printf("map(md5) %s:%s\n",hash,password)
	
		//var shalookup map[string]string
		go shamap(password,chsha)
		//for testing, warning dump
		//fmt.Printf("map(sha) %s:%s\n",hash,password)
		shalookup[<-chsha] = password
		md5lookup[<-chmd5] = password

	} */

	//TODO
	//itterate through a file (look in the guessSingle function above)
	//rather than check for equality add each hash:passwd entry to a map SHA and MD5 where the key = hash and the value = password
	//TODO at the very least use go subroutines to generate the sha and md5 hashes at the same time
	//OPTIONAL -- Can you use workers to make this even faster

	//TODO create a test in hscan_test.go so that you can time the performance of your implementation
	//Test and record the time it takes to scan to generate these Maps
	// 1. With and without using go subroutines
	// 2. Compute the time per password (hint the number of passwords for each file is listed on the site...)
//}

/* func GetSHA(hash string) (string, error) {
	password, ok := shalookup[hash]
	if ok {
		fmt.Printf("password found (shalookup) %s\n",password)
		return password, nil
	} else {
		fmt.Printf("password not found (shalookup)\n")
		return "", errors.New("password does not exist")

	}
}

//TODO
func GetMD5(hash string) (string, error) {
	password, ok := md5lookup[hash]
	if ok {
		fmt.Printf("password found (md5lookup) %s\n",password)
		return password, nil

	} else {
		fmt.Printf("password not found (shalookup)\n")
		return "", errors.New("password does not exist")

	}
} */
