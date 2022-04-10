package hscan

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"
)

//==========================================================================\\
//303872
var shalookup = make(map[string]string)
var md5lookup = make(map[string]string)

func GuessSingle(sourceHash string, filename string) string{

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
}
func md5map(password string, ch chan string){
	ch <- fmt.Sprintf("%x", md5.Sum([]byte(password)))
}
func shamap(password string, ch chan string){
	ch <- fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
}
func GenHashMaps(filename string) {

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

	}

	//TODO
	//itterate through a file (look in the guessSingle function above)
	//rather than check for equality add each hash:passwd entry to a map SHA and MD5 where the key = hash and the value = password
	//TODO at the very least use go subroutines to generate the sha and md5 hashes at the same time
	//OPTIONAL -- Can you use workers to make this even faster

	//TODO create a test in hscan_test.go so that you can time the performance of your implementation
	//Test and record the time it takes to scan to generate these Maps
	// 1. With and without using go subroutines
	// 2. Compute the time per password (hint the number of passwords for each file is listed on the site...)
}

func GetSHA(hash string) (string, error) {
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
}
