package main
/* WebSite Check
monitoring and scanning the directory of a website to protect him

- Signatures files from https://github.com/redteamcaliber/WebMalwareScanner
- Option to use virtus total to check file

--langagues supported
-php
-js

Based on project:
- https://www.owasp.org/index.php/OWASP_Web_Malware_Scanner_Project
- https://github.com/redteamcaliber/WebMalwareScanner
*/
import (
  "fmt"
  "os"
  "encoding/json"
  "io/ioutil"
  "path/filepath"
  "flag"
  "bufio"
  "strings"
  "regexp"
  "github.com/fsnotify/fsnotify"
  "time"
  "net/url"
  "net/http"
  "bytes"
  "mime/multipart"
  "io"
  "github.com/fatih/color"


)

type Filedata struct {
  Name      string
  Size      string
  Hash      string
  Positives int64
}

type Malware struct {
  Name        string `json:"Malware_Name"`
  Signatures  []string `json:"Malware_Signatures"`
}

type Database struct {
  DBName  string `json:"Database_Name"`
  DBFileType  string `json:"Database_File_Type"`
  List    []Malware `json:"Database_Signatures"`
}

type ScanResult struct {
  Response  int64   `json:"response_code"`
  ScanDate  string  `json:"scan_date"`
  Total     int64   `json:"total"`
  Positives int64   `json:"positives"`
  Permalink string  `json:"permalink"`
  Message   string  `json:"verbose_msg"`
  Sha256    string  `json:"sha256"`
  Md5       string  `json:"md5"`
}

type ScanRequest struct {
  Permalink   string  `json:"permalink"`
  Resource    string  `json:"resource"`
  Response    int64   `json:"response_code"`
  ScanId      string  `json:"scan_id"`
  Message     string  `json:"verbose_msg"`
  Sha256      string  `json:"sha256"`
  ScanDate    string  `json:"scan_date"`
  UrlAddress  string  `json:"url"`
}

var DBSignaturesPHP Database
var DBSignaturesJS  Database
const APIKEY = ""
var watcher *fsnotify.Watcher

func ScanFileResult(scanrequest ScanRequest) ScanResult {
  var scanresult ScanResult
  hc := http.Client{}
  form := url.Values{}
  form.Add("apikey", APIKEY)
  form.Add("resource", scanrequest.Resource)

  req, err := http.NewRequest("POST", "https://www.virustotal.com/vtapi/v2/file/scan", strings.NewReader(form.Encode()))
  req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
  res, err := hc.Do(req)
	if err != nil {
		return scanresult
	}

	// Check the response
  if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
    return scanresult
	} else {
    decoder := json.NewDecoder(res.Body)
    err = decoder.Decode(&scanresult)
  }
  return scanresult

}

func ScanFileRequest(path string) ScanRequest {
  var scanrequest ScanRequest

	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	f, err := os.Open(path)
	if err != nil {
		return scanrequest
	}
	defer f.Close()
	fw, err := w.CreateFormFile("file", path)
	if err != nil {
    scanrequest.Response=-10
		return scanrequest
	}
	if _, err = io.Copy(fw, f); err != nil {
    scanrequest.Response=-10
		return scanrequest
	}


	if fw, err = w.CreateFormField("apikey"); err != nil {
    scanrequest.Response=-10
		return scanrequest
	}
	if _, err = fw.Write([]byte(APIKEY)); err != nil {
    scanrequest.Response=-10
		return scanrequest
	}

	w.Close()

	req, err := http.NewRequest("POST", "https://www.virustotal.com/vtapi/v2/file/report", &b)
	if err != nil {
    scanrequest.Response=-10
		return scanrequest
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
    scanrequest.Response = -10
		return scanrequest
	}

	// Check the response
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
	} else {
    decoder := json.NewDecoder(res.Body)
    err = decoder.Decode(&scanrequest)
  }
  return scanrequest
}


 func CheckSignaturesOnFile(path string, database Database, vt bool) {
//   var database Database
  if database.DBName != "" && len(database.List) > 0 {
    f, err := os.Open(path)
    if err != nil {
      fmt.Println(err)
    }
    defer f.Close()
    scanner := bufio.NewScanner(f)
    line := 1
    for scanner.Scan() {
      i:=0
      for i < len(database.List) {
        j:=0
        for j < len(database.List[i].Signatures) {
         //Search based on regex case Insensitive
          re := regexp.MustCompile("(?i)"+database.List[i].Signatures[j])
	         if len(re.Find([]byte(strings.Replace(scanner.Text()," ","",-1)))) > 0 {
             color.Red("\t\tWARNING: %s\n",database.List[i].Name)
             fmt.Printf("\t\tOn file %s\n",path)
             fmt.Printf("\t\tLine %d\n",line)
           }
           j++
         }
         i++
       }
       line++
     }
}
 if vt == true {
   fmt.Printf("\tVirus total check\n")
   scanfilerequest := ScanFileRequest(path)
   if scanfilerequest.Response == -10 {
     color.Red("\tError on request\n")
     return
   }
   var scanfileresult ScanResult
   scanfileresult.Response = -2

   for scanfileresult.Response == -2 {
     time.Sleep(25 * time.Second)
     scanfileresult = ScanFileResult(scanfilerequest)
   }
   if scanfileresult.Positives > 0 {
      color.Red("\t\tWarning: File infected\n")
      color.Red("\t\tMore info %s\n",scanfileresult.Permalink)
   } else {
     color.Green("\t\tOK\n")
   }
}
 // if err := scanner.Err(); err != nil {
 // }

 }

func LoadDatabase(extension string) Database {
  //load signatures
  var database Database
  if _,err := os.Stat("Signatures/signatures_"+extension+".json"); err == nil {
      cg,_:= ioutil.ReadFile("Signatures/signatures_"+extension+".json")
      //database := Database{}
      _= json.Unmarshal([]byte(cg),&database)
      fmt.Printf("\tDatabase was loaded\n")

    } else if os.IsNotExist(err) {
      fmt.Println("I can't find signatures_",extension,".json")

    } else {
        fmt.Println("Something goes wrong")
        fmt.Println(err)
    }
    return database
}

func ScanFileForSignatures(file string, vt bool) {
  extension := filepath.Ext(file)
  switch extension {
  case ".php":
    if len(DBSignaturesPHP.List) == 0 {
      fmt.Printf("\tLoading DB Signatures for PHP files\n")
      DBSignaturesPHP = LoadDatabase("php")
    }
    fmt.Printf("\tScanning file %s\n",file)
    CheckSignaturesOnFile(file,DBSignaturesPHP, vt)
  case ".js":
    if len(DBSignaturesJS.List) == 0 {
      fmt.Printf("\tLoading DB Signatures for JS files\n")
      DBSignaturesJS = LoadDatabase("js")
    }
    fmt.Printf("\tScanning file %s\n",file)
    CheckSignaturesOnFile(file,DBSignaturesJS, vt)
  default:
    fmt.Printf("\tExtension not supported for signatures check (yet) (%s)\n",file)
    CheckSignaturesOnFile(file,Database{},vt)

  }
}

func ScanDirectory(path string, vt bool) error {
  fmt.Println("Scanning dir: ",path)
  //reg, _ := regexp.Compile("[a-zA-z0-9]+")
//basedir := reg.ReplaceAllString(path,"")
  err := filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
    if !info.IsDir() {
      ScanFileForSignatures(file, vt)
    }
    return nil
  })
  return err
}

func watchDir(path string, fi os.FileInfo, err error) error {
	if fi.Mode().IsDir() {
		return watcher.Add(path)
	}
	return nil
}

func MonitoringDirectory(path string,vt bool) {
	watcher, _ = fsnotify.NewWatcher()
	defer watcher.Close()

	if err := filepath.Walk(path, watchDir); err != nil {
		fmt.Println("ERROR", err)
	}
	done := make(chan bool)

	go func() {
		for {
			select {
			// watch for events
			case event := <-watcher.Events:
        if event.Op&fsnotify.Chmod == fsnotify.Chmod || event.Op&fsnotify.Create == fsnotify.Create {
          ScanFileForSignatures(event.Name,vt)
        }

				// watch for errors
			case err := <-watcher.Errors:
				fmt.Println("ERROR", err)
			}
		}
	}()

	<-done
}

func main() {
  //check subcommand
  scanCmd := flag.NewFlagSet("scan",flag.ExitOnError)
  monitorCmd := flag.NewFlagSet("monitor",flag.ExitOnError)
  if len(os.Args) < 3 {
    fmt.Println("expected scan or monitor parameter.")
    fmt.Printf("\twebsite_scan scan -path/var/www/html\n")
    fmt.Printf("\twebsite_scan monitor -path=/var/www/html -vt\n")
  } else {
      switch os.Args[1] {
      case "scan":
        path := scanCmd.String("path","","path to the directory")
        vt := scanCmd.Bool("vt",false,"virus total option")
        scanCmd.Parse(os.Args[2:])
        fmt.Println("Start scanning ")
        ScanDirectory(*path,*vt)
      case "monitor":
        path := monitorCmd.String("path","","path to the directory")
        vt := monitorCmd.Bool("vt",false,"virus total option")
        monitorCmd.Parse(os.Args[2:])
        fmt.Println("Starting monitoring ")
        MonitoringDirectory(*path,*vt)
      default:
        fmt.Println("There are scan or monitor option")

      }
  }
  return
}
