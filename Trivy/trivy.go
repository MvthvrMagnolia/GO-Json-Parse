//import packages and libraries
package main

 
import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/olekukonko/tablewriter"
)

//2.declare list type(struct) and variable for the printed output

type Results struct {
	Results []PrintData
}

//3.declare the contents of the list variables according to data type in json data; considering arrays/objects etc

type PrintData struct {
	Vulnerabilities []struct {
		Title string `json: "Title"`
		SeveritySource string `json: "SeveritySource"`
		CVSS struct {
			Nvd struct {
				score float64 `json:"V3Score"`
			}
		}
	}
}

  //4.Write the function that'll executed including try/catch
func main() {
	
	filename := os.Args[1]
	data, err := ioutil.ReadFile(filename)
	if err != nil {
			fmt.Printf("error reading file")
			os.Exit(1)
	}
var jsonData Results
var output [][]string
 
 //5. Declare table writer for the unmarshall function used to parse the json
   
 table := tablewriter.NewWriter(os.Stdout)                   
	table.SetHeader([]string{"title", "severitysource", "score"}) 
	json.Unmarshal(data, &jsonData)
 
	//6. Use the for loop and nested for loop to loop through arrays/objects within arrays in the json data to get information
	
    for i := 0; i < len(jsonData.Results); i++ {  
		vulnData := jsonData.Results[i].Vulnerabilities 
		for j := 1; j < len(vulnData); j++ {   
			title := vulnData[j].Title
			severitysource := vulnData[j].SeveritySource
			score := vulnData[j].CVSS.Nvd.score
			output = append(output, []string{title, severitysource, fmt.Sprint(score)})
		}
        
	
	}
 //7. Append the output bulk to the tablewriter/SetAlignment
	
    table.AppendBulk(output)                   
	table.SetAlignment(tablewriter.ALIGN_LEFT) 
	table.Render()   //display the table                          
} 




