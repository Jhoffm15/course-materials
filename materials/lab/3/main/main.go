// Build and Use this File to interact with the shodan package
// In this directory lab/3/shodan/main:
// go build main.go
// SHODAN_API_KEY=YOURAPIKEYHERE ./main <search term>

package main

import (
	"fmt"
	"log"
	"os"
	"encoding/json"
	"shodan/shodan"
	"strconv"
)

func main() {
	if (len(os.Args) != 2) && (len(os.Args) != 3){
		log.Fatalln("Usage: main <searchterm> [page]")
	}
	apiKey := os.Getenv("SHODAN_API_KEY")
	s := shodan.New(apiKey)
	info, err := s.APIInfo()
	if err != nil {
		log.Panicln(err)
	}
	fmt.Printf(
		"Query Credits: %d\nScan Credits:  %d\n\n",
		info.QueryCredits,
		info.ScanCredits)
	i := 1
	if len(os.Args) == 3{
		var e error
		i, e = strconv.Atoi(os.Args[2])
		if e != nil{
			log.Panicln(err)
		}
	}else{
		i=1
	}
	newRequest := "R"
	istr := ""
	search := os.Args[1]
	for newRequest == "R" {
		nextPage := "Y"
		for nextPage == "Y"{
			hostSearch, err := s.HostSearch(search,i)
			
			
			if err != nil {
				log.Panicln(err)
			}

			fmt.Printf("Host Data Dump\n")
			for _, host := range hostSearch.Matches {
				fmt.Println("==== start ",host.IPString,"====")
				h,_ := json.Marshal(host)
				fmt.Println(string(h))
				fmt.Println("==== end ",host.IPString,"====")
				//fmt.Println("Press the Enter Key to continue.")
				//fmt.Scanln()
			}


			fmt.Printf("IP, Port\n")

			for _, host := range hostSearch.Matches {
				fmt.Printf("%s, %d\n", host.IPString, host.Port)
			}

			fmt.Println("Press Y and enter to get next page.")
			fmt.Scanln(&nextPage)
			i++
		}
		fmt.Println("Press R and enter to make a new request, write request string then enter then page number and enter.")
		fmt.Scanln(&newRequest)
		if newRequest == "R"{
			fmt.Scanln(&search);
			fmt.Scanln(&istr);
			var e error
			i, e = strconv.Atoi(istr)
			if e != nil{
				log.Panicln(err)
			}
		}
	}
}