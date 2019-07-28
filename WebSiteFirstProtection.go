package main

import (
  "fmt"
  "os"
  "encoding/json"
  "io/ioutil"
  "path/filepath"
  "flag"
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
  "crypto/md5"
  "encoding/hex"
)

type Filedata struct {
  Name      string
  Malware   string
}

type Malware struct {
  Name        string `json:"Malware_Name"`
  Signatures  []string `json:"Malware_Signatures"`
}

type Database struct {
  DBName      string `json:"Database_Name"`
  DBFileType  string `json:"Database_File_Type"`
  List        []Malware `json:"Database_Signatures"`
}

type Whitelist struct {
  Name  string `json:"name"`
  Hash  string `json:"md5"`
}

type FinalReport struct {
  TotalFiles  int64
  Positives   int64
  Files       []Filedata
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
var logoutput bool
const layout = "2006-01-02T15:04:05"
var whitelist []Whitelist
var finalReport FinalReport

func ScanFileResult(scanrequest ScanRequest) ScanResult {
  var scanresult ScanResult
  scanresult.Response = -10
  hc := http.Client{}
  form := url.Values{}
  form.Add("apikey", APIKEY)
  form.Add("resource", scanrequest.Resource)

  req, err := http.NewRequest("POST", "https://www.virustotal.com/vtapi/v2/file/report", strings.NewReader(form.Encode()))
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

func LoadWithlist() {
  if _,err := os.Stat("whitelist.json"); err == nil {
      cg,_:= ioutil.ReadFile("whitelist.json")
      _= json.Unmarshal([]byte(cg),&whitelist)
      if logoutput {
        fmt.Println((time.Now()).Format(layout),"| Notice | Whitelist OK")
      } else {
        fmt.Printf("Whitelist loaded\n")
      }
    } else if os.IsNotExist(err) {
      if logoutput {
        fmt.Println((time.Now()).Format(layout),"| Notice | There isn't Whitelist file")
      } else {
        fmt.Println("There isn't Whitelist file")
      }
    } else {
      if logoutput {
        fmt.Println((time.Now()).Format(layout),"| Alert | Something goes wrong")
      } else {
        fmt.Println("Something goes wrong")
        fmt.Println(err)
      }
    }
}

func InWhiteList(filename string, hash string) bool {
  for _, item := range whitelist {
    if item.Name == filename && item.Hash == hash {
      if logoutput {
        fmt.Println((time.Now()).Format(layout),"| Notice |  Whitelist |",filename)
      } else {
        fmt.Println("\tWhitelist for ",filename)
      }
      return true
    }
  }
  return false
}

func ScanFileRequest(path string) ScanRequest {
  var scanrequest ScanRequest
  scanrequest.Response=-10
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	f, err := os.Open(path)

	if err != nil {
		return scanrequest
	}
	defer f.Close()
  h := md5.New()

  if _, err = io.Copy(h,f); err != nil {
    if logoutput {
      fmt.Println((time.Now()).Format(layout),"| Error | Copy File |",path)
    } else {
      fmt.Println(err)
    }
    return scanrequest
  }
  if InWhiteList(filepath.Base(path),hex.EncodeToString(h.Sum(nil))) {
    scanrequest.Response = -9
    return scanrequest
  }
  f.Seek(0,io.SeekStart)
	fw, err := w.CreateFormFile("file", path)
	if err != nil {
		return scanrequest
	}
	if _, err = io.Copy(fw, f); err != nil {
		return scanrequest
	}
	if fw, err = w.CreateFormField("apikey"); err != nil {
		return scanrequest
	}
	if _, err = fw.Write([]byte(APIKEY)); err != nil {
		return scanrequest
	}
	w.Close()

	req, err := http.NewRequest("POST", "https://www.virustotal.com/vtapi/v2/file/scan", &b)
	if err != nil {
		return scanrequest
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return scanrequest
	}
	// Check the response
	if res.StatusCode != http.StatusOK {
    if logoutput {
      fmt.Println((time.Now()).Format(layout),"| Bad Status Code |",res.Status)
    } else {
        err = fmt.Errorf("bad status: %s", res.Status)
    }
	} else {
    decoder := json.NewDecoder(res.Body)
    err = decoder.Decode(&scanrequest)
  }
  return scanrequest
}

func ScanFileOnVt(path string) bool {
  var scanfileresult ScanResult
  var scanfilerequest ScanRequest

  scanfileresult.Response = -2
  if ! logoutput {
     fmt.Printf("\tVirus total check\n")
  }
  scanfilerequest = ScanFileRequest(path)
  if scanfilerequest.Response == -10 {
    if logoutput {
      fmt.Println((time.Now()).Format(layout),"| Error | Request Virustotal")
    } else {
      color.Red("\tError on request\n")
    }
    return false
  }
  for scanfileresult.Response == -2 {
    time.Sleep(25 * time.Second)
    scanfileresult = ScanFileResult(scanfilerequest)
  }
  if scanfileresult.Positives > 0 {
    if logoutput {
      fmt.Println((time.Now()).Format(layout),"| Warning | File infected | VirusTotal |",path,"|",scanfileresult.Permalink)
    } else {
      color.Red("\t\tWarning: File infected\n")
      color.Red("\t\tMore info %s\n",scanfileresult.Permalink)
    }
    return true

  } else {
    if logoutput {
      fmt.Println((time.Now()).Format(layout),"| Ok | VirusTotal |",scanfileresult.Permalink)
    } else {
      color.Green("\t\tOK\n")
    }
  }
  return false
}

 func CheckSignaturesOnFile(path string, database Database, vt bool) (bool, string) {

  if database.DBName != "" && len(database.List) > 0 {
    f, err := ioutil.ReadFile(path)
    //f, err := os.Open(path)
    if err != nil {
      if logoutput {
        fmt.Println((time.Now()).Format(layout),"| Error | Open File |",path)
      } else {
        fmt.Println(err)
      }
      return false, ""
    }
    h := md5.New()
    if _, err = io.WriteString(h,string(f)); err != nil {
     if logoutput {
       fmt.Println((time.Now()).Format(layout),"| Error | Copying file |",path)
     } else {
       fmt.Println(err)
     }
     return false, ""
    }
    if InWhiteList(filepath.Base(path),hex.EncodeToString(h.Sum(nil))) {
     return false, ""
    }
    f_nospaces := strings.Replace(string(f)," ","",-1)
    f_nolines := strings.Replace(f_nospaces,"\n","",-1)
    for _, malware := range database.List {
      for _, signature := range malware.Signatures {
       //Search based on regex case Insensitive
        re := regexp.MustCompile("(?i)"+signature)
         if len(re.Find([]byte(strings.Replace(f_nolines," ","",-1)))) > 0 {
           if logoutput {
             fmt.Println((time.Now()).Format(layout),"| Warning | File infected |",malware.Name,"|",path)
           } else {
             color.Red("\t\tWARNING: %s\n",malware.Name)
             color.Red("\t\tPattern: %s\n",signature)
             fmt.Printf("\t\tOn file %s\n",path)
           }
           return true, malware.Name
         }
       }
     }
     return false, ""
 }
 if vt == true {
   if ScanFileOnVt(path) {
     return true, "VirusTotal Detection"
   }
 }
 return false, ""
}

func LoadDatabase(extension string) Database {
  //load signatures
  var database Database
  if _,err := os.Stat("Signatures/signatures_"+extension+".json"); err == nil {
      cg,_:= ioutil.ReadFile("Signatures/signatures_"+extension+".json")
      //database := Database{}
      _= json.Unmarshal([]byte(cg),&database)
      if logoutput {
        fmt.Println((time.Now()).Format(layout),"| Notice | Database was loaded")
      } else {
        fmt.Printf("\tDatabase was loaded\n")
      }
    } else if os.IsNotExist(err) {
      if logoutput {
        fmt.Println((time.Now()).Format(layout),"| Alert | Can't find signatures file signatures",extension,".json")
      } else {
        fmt.Println("I can't find signatures_",extension,".json")
      }
    } else {
      if logoutput {
        fmt.Println((time.Now()).Format(layout),"| Alert | Something goes wrong")
      } else {
        fmt.Println("Something goes wrong")
        fmt.Println(err)
      }
    }
    return database
}

func ScanFileForSignatures(file string, vt bool) (bool, string) {
  var malware string
  var positive bool

  extension := filepath.Ext(file)
  switch extension {
  case ".php":
    if len(DBSignaturesPHP.List) == 0 {
      if logoutput {
        fmt.Println((time.Now()).Format(layout),"| Notice | Loading DB Signatures for PHP files")
      } else {
        fmt.Printf("\tLoading DB Signatures for PHP files\n")
      }
      DBSignaturesPHP = LoadDatabase("php")
    }
    if ! logoutput {
      fmt.Printf("\tScanning file %s\n",file)
    }
    positive,malware = CheckSignaturesOnFile(file,DBSignaturesPHP, vt)
  case ".js":
    if len(DBSignaturesJS.List) == 0 {
      if logoutput {
        fmt.Println((time.Now()).Format(layout),"| Notice | Loading DB Signatures for JS files")
      } else {
        fmt.Printf("\tLoading DB Signatures for JS files\n")
      }
      DBSignaturesJS = LoadDatabase("js")
    }
    if ! logoutput {
      fmt.Printf("\tScanning file %s\n",file)
    }
    positive,malware = CheckSignaturesOnFile(file,DBSignaturesJS, vt)

  default:
    if logoutput {
      fmt.Println((time.Now()).Format(layout),"| Notice | Extension not suppported for signatures check |",extension)
    } else {
      fmt.Printf("\tExtension not supported for signatures check (yet) (%s)\n",file)
    }
    positive, malware = CheckSignaturesOnFile(file,Database{},vt)
  }
  return positive,malware
}

func ScanDirectory(path string, vt bool) error {

  if ! logoutput {
    fmt.Println("Scanning dir: ",path)
  }
  err := filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
    if !info.IsDir() {
      finalReport.TotalFiles += 1
      positive, malware := ScanFileForSignatures(file, vt)
      if positive {
        finalReport.Positives += 1
        filedata := Filedata{}
        filedata.Name = info.Name()
        filedata.Malware = malware
        finalReport.Files = append(finalReport.Files, filedata)
      }
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
    if logoutput {
      fmt.Println((time.Now()).Format(layout),"| Error | Directory")
    } else {
		    fmt.Println("ERROR", err)
    }
	}
	done := make(chan bool)

	go func() {
		for {
			select {
			// watch for events
			case event := <-watcher.Events:

        if event.Op&fsnotify.Chmod == fsnotify.Chmod || event.Op&fsnotify.Create == fsnotify.Create {
          if logoutput {
            fmt.Println((time.Now()).Format(layout),"| Event |",event.Op,"|",event.Name)
          }
          ScanFileForSignatures(event.Name,vt)
        }

				// watch for errors
			case err := <-watcher.Errors:
        if logoutput {
          fmt.Println((time.Now()).Format(layout)," |Error | Read Directory")
        } else {
				  fmt.Println("ERROR", err)
        }
			}
		}
	}()

	<-done
}

func main() {
  scanCmd := flag.NewFlagSet("scan",flag.ExitOnError)
  monitorCmd := flag.NewFlagSet("monitor",flag.ExitOnError)

  if len(os.Args) < 3 {
    fmt.Println("expected scan or monitor parameter.")
    fmt.Printf("\twebsite_scan scan -path/var/www/html\n")
    fmt.Printf("\twebsite_scan monitor -path=/var/www/html -vt -log\n")
  } else {
      switch os.Args[1] {
      case "scan":
        path := scanCmd.String("path","","path to the directory")
        vt := scanCmd.Bool("vt",false,"virus total option")
        out := scanCmd.Bool("log",false,"Output Option")

        scanCmd.Parse(os.Args[2:])
        logoutput = *out
        if logoutput {
          fmt.Println((time.Now()).Format(layout),"| Notice | Start Scan |",*path)
        } else {
            fmt.Println("Starting scanning")
        }
        LoadWithlist()
        ScanDirectory(*path,*vt)
        if logoutput {
          fmt.Println((time.Now()).Format(layout),"| Notice | End Scan |", finalReport.TotalFiles,"|", finalReport.Positives)
        } else {
          fmt.Println("End Scan")
          fmt.Println("Total Files Scanned: ",finalReport.TotalFiles)
          fmt.Println("Total Positives:     ",finalReport.Positives)
        }
      case "monitor":
        path := monitorCmd.String("path","","path to the directory")
        vt := monitorCmd.Bool("vt",false,"virus total option")
        out := monitorCmd.Bool("log",false,"Output Option")

        monitorCmd.Parse(os.Args[2:])
        logoutput = *out

        if logoutput {
          fmt.Println((time.Now()).Format(layout),"| Notice | Start Monitor |",*path)
        } else {
            fmt.Println("Start Monitor")
        }
        LoadWithlist()
        MonitoringDirectory(*path,*vt)
      default:
        fmt.Println("There are scan or monitor option")

      }
  }
  return
}
