// bhg-scanner/scanner.go modified from Black Hat Go > CH2 > tcp-scanner-final > main.go
// Code : https://github.com/blackhat-go/bhg/blob/c27347f6f9019c8911547d6fc912aa1171e6c362/ch-2/tcp-scanner-final/main.go
// License: {$RepoRoot}/materials/BHG-LICENSE
// Useage:
// {TODO 1: FILL IN}

package scanner

import (
	"fmt"
	"net"
	"sort"
	"time"
)

//TODO 3 : ADD closed ports; currently code only tracks open ports
var openports []int  // notice the capitalization here. access limited!
var closedports []int


func worker(ports, results chan int) {
	for p := range ports {
		address := fmt.Sprintf("scanme.nmap.org:%d", p)    
		conn, err := net.DialTimeout("tcp", address, 200 * time.Millisecond) // TODO 2 : REPLACE THIS WITH DialTimeout (before testing!)
		if err != nil { 
			results <- 0
			continue
		}
		conn.Close()
		results <- p
	}
}

// for Part 5 - consider
// easy: taking in a variable for the ports to scan (int? slice? ); a target address (string?)?
// med: easy + return  complex data structure(s?) (maps or slices) containing the ports.
// hard: restructuring code - consider modification to class/object 
// No matter what you do, modify scanner_test.go to align; note the single test currently fails
func PortScanner(min, max int) (int,int) {  
	openports = nil
	closedports = nil
	ports := make(chan int, 100)   // TODO 4: TUNE THIS FOR CODEANYWHERE / LOCAL MACHINE
	results := make(chan int, 100)

	for i := 0; i < cap(ports); i++ {
		go worker(ports, results)
	}

	go func() {
		for i := 0; i <= 1024; i++ {
			ports <- i
		}
	}()

	for i := 0; i < 1024; i++ {
		port := <-results
		if port != 0 {
			openports = append(openports, port)
		}
	}
	k := 0
	for i := 0; i < 1024; i++{
		if openports[k] == i {
			k++
			if k >= len(openports){
				k = 0
			}
		}else{
			closedports = append(closedports,i)
		}
	}

	close(ports)
	close(results)
	sort.Ints(openports)
	//sort.Ints(closedports)

	//TODO 5 : Enhance the output for easier consumption, include closed ports
	fmt.Printf(" ---------- Open Ports ---------- \n");
	for _, port := range openports {
		fmt.Printf("%d \n", port)
	}
	fmt.Printf(" --------- Closed Ports --------- \n");
	for i, port := range closedports {
		if i %20 == 0{
			fmt.Printf("\n");
		}
		fmt.Printf("%4d ", port)
	}

	return len(openports),len(closedports) // TODO 6 : Return total number of ports scanned (number open, number closed); 
	//you'll have to modify the function parameter list in the defintion and the values in the scanner_test
}
