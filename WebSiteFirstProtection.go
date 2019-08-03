package main

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
  "crypto/md5"
  "encoding/hex"
  "github.com/rwcarlsen/goexif/exif"
  "github.com/rwcarlsen/goexif/tiff"
  "github.com/go-telegram-bot-api/telegram-bot-api"
  "strconv"
)

type FileSignature struct {
  Signature string `json:"Signature"`
  Text      string `json:"Text"`
}

type Filedata struct {
  Name      string  `json:"Filename"`
  Malware   string  `json:"Malware_Name"`
  Signature []FileSignature `json:"Description"`
}

type Malware struct {
  Name        string    `json:"Malware_Name"`
  Signatures  []string  `json:"Malware_Signatures"`
  Method      string    `json:"Rule_Method"`
  Status      string    `json:"Rule_Status"`
}

type Database struct {
  DBName      string    `json:"Database_Name"`
  DBFileType  string    `json:"Database_File_Type"`
  List        []Malware `json:"Database_Signatures"`
}

type Whitelist struct {
  Name  string `json:"name"`
  Hash  string `json:"md5"`
}

type FinalReport struct {
  Path        string      `json:"Path"`
  TotalFiles  int64       `json:"Total"`
  Positives   int64       `json:"Positives"`
  Date        string      `json:"Date"`
  Files       []Filedata  `json:"Infected_Files"`
}

type VTScan struct {
  File    string
  Result  ScanResult
  Request ScanRequest
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
var DBSignaturesIMG Database
const APIKEY = ""
const TelegramKEY = ""
var watcher *fsnotify.Watcher
var logOption bool
var telegramOption bool
const layout = "2006-01-02T15:04:05"
var whitelist []Whitelist
var finalReport FinalReport
var TelegramUsers []int64 //`json:"users"`

/*
  TELEGRAM FUNCTIONS
*/

//LoadTelegramUsers load users ID from telegram.users file and fill TelegramUsers slice.
//Users in telegram.users are one by line
func LoadTelegramUsers() {
  fd, err := os.Open("telegram.users")
    if err != nil {
        return
    }
    defer fd.Close()

  if err != nil {
    return
  }
  scanner := bufio.NewScanner(fd)
    scanner.Split(bufio.ScanWords)
    for scanner.Scan() {
        x, err := strconv.Atoi(scanner.Text())
        if err != nil {
            return
        }
        TelegramUsers = append(TelegramUsers, int64(x))
    }
}

func SendTelegramAlert(event string, file string, malware string) {
  //fmt.Println("\t**Send Alert**")
  bot, err := tgbotapi.NewBotAPI(TelegramKEY)
	if err != nil {
		return
	}
	bot.Debug = true
  message := "<b>"+event+"</b>\n<b>FILE:</b> <i>"+file+"</i>\n<b>MALWARE:</b><i> "+malware+"</i>"
  for _,user := range TelegramUsers {
    msg := tgbotapi.NewMessage(user, message)
    msg.ParseMode = "html"
    bot.Send(msg)
  }
}

//SendTelegramMessage receive a type of message and the text of the message to send to all users
func SendSummaryReport() {
  //fmt.Println("Send Report")
  bot, err := tgbotapi.NewBotAPI(TelegramKEY)
	if err != nil {
		return
	}
	bot.Debug = false

  message := "<strong>Summary Report</strong>\n<b>Date:</b><i> "+finalReport.Date+"</i>\n<b>Total Scaned Files:</b> "+strconv.Itoa(int(finalReport.TotalFiles))+"\n<b>Infected Files:</b> "+strconv.Itoa(int(finalReport.Positives))+"\nCheck Infected Files using /lastreport command"
  message += "\n<b>END</b>"
  for _,user := range TelegramUsers {
        msg := tgbotapi.NewMessage(user, message)
        msg.ParseMode = "html"
        bot.Send(msg)
  }
}

/*
VIRUS TOTAL FUNCTIONS Functions
*/

// Scan manage VirtusTotal send and request files. Return the number of positives or -1 for error
func (vt VTScan) Scan(path string) int64 {

  vt.File = path
  if vt.request() {
    for vt.result() {
      if vt.Result.Response != -2 {
        break
      }
      time.Sleep(25 * time.Second)

      //scanfileresult = vt.result()
    }
    if vt.Request.Response == 2 {
      return vt.Result.Positives
    }
  }
  return -1
}

//result result from Virtus Total
func (vt VTScan) result() bool {
  //var scanresult ScanResult
  vt.Result.Response = - 10
  //scanresult.Response = -10
  hc := http.Client{}
  form := url.Values{}
  form.Add("apikey", APIKEY)
  form.Add("resource", vt.Request.Resource)

  req, err := http.NewRequest("POST", "https://www.virustotal.com/vtapi/v2/file/report", strings.NewReader(form.Encode()))
  req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
  res, err := hc.Do(req)
	if err != nil {
		return false
	}
	// Check the response
  if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
    return false
	} else {
    decoder := json.NewDecoder(res.Body)
    err = decoder.Decode(&vt.Result)
  }
  return true
}

func (vt VTScan) request() bool {
  //var scanrVTResult.vequest ScanRequest
  vt.Request.Response=-10
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	f, err := os.Open(vt.File)

	if err != nil {
		return false
	}
	defer f.Close()
  h := md5.New()

  if _, err = io.Copy(h,f); err != nil {
    if logOption {
      fmt.Println((time.Now()).Format(layout),"| Error | Copy File |",vt.File)
    } else {
      fmt.Println(err)
    }
    return false
  }
  if InWhiteList(vt.File) {
    vt.Request.Response = -9
    return false
  }
  f.Seek(0,io.SeekStart)
	fw, err := w.CreateFormFile("file", vt.File)
	if err != nil {
		return false
	}
	if _, err = io.Copy(fw, f); err != nil {
		return false
	}
	if fw, err = w.CreateFormField("apikey"); err != nil {
		return false
	}
	if _, err = fw.Write([]byte(APIKEY)); err != nil {
		return false
	}
	w.Close()

	req, err := http.NewRequest("POST", "https://www.virustotal.com/vtapi/v2/file/scan", &b)
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return false
	}
	// Check the response
	if res.StatusCode != http.StatusOK {
    if logOption {
      fmt.Println((time.Now()).Format(layout),"| Bad Status Code |",res.Status)
    } else {
        err = fmt.Errorf("bad status: %s", res.Status)
    }
	} else {
    decoder := json.NewDecoder(res.Body)
    err = decoder.Decode(&vt.Request)
    return true
  }
  return false
}

func ScanFileOnVt(path string) (bool, string) {
  var vt VTScan

  vt.Result.Response = -2
  if ! logOption {
     fmt.Printf("\tVirus total check\n")
  }
  if vt.Scan(path) < 0 {
    if logOption {
      fmt.Println((time.Now()).Format(layout),"| Error | Request Virustotal")
    } else {
      color.Red("\tError on request\n")
    }
    return false,""
  }
  if vt.Result.Positives > 0 {
    if logOption {
      fmt.Println((time.Now()).Format(layout),"| Warning | File infected | VirusTotal |",path,"|",vt.Result.Permalink)
    } else {
      color.Red("\t\tWarning: File infected\n")
      color.Red("\t\tMore info %s\n",vt.Result.Permalink)
    }
    return true, "Virtus Total Detection"
  } else {
    if logOption {
      fmt.Println((time.Now()).Format(layout),"| Ok | VirusTotal |",vt.Result.Permalink)
    } else {
      color.Green("\t\tOK\n")
    }
  }
  return false, ""
}

/*

WHITE LIST FUNCTIONS
*/

func LoadWhitelist() {
  if _,err := os.Stat("whitelist.json"); err == nil {
      cg,_:= ioutil.ReadFile("whitelist.json")
      _= json.Unmarshal([]byte(cg),&whitelist)
    } else if os.IsNotExist(err) {
      if logOption {
        fmt.Println((time.Now()).Format(layout),"| Notice | There isn't Whitelist file")
      } else {
        fmt.Println("There isn't Whitelist file")
      }
    } else {
      if logOption {
        fmt.Println((time.Now()).Format(layout),"| Alert | Something goes wrong")
      } else {
        fmt.Println("Something goes wrong")
        fmt.Println(err)
      }
    }
}

func InWhiteList(path string) bool {

  f,_ := ioutil.ReadFile(path)
  filename := filepath.Base(path)

  h := md5.New()
  if _, err := io.WriteString(h,string(f)); err != nil {
   if logOption {
     fmt.Println((time.Now()).Format(layout),"| Error | Copying file |",path)
   } else {
     fmt.Println(err)
   }
   return false
  }

  md5sum := hex.EncodeToString(h.Sum(nil))

  for _, item := range whitelist {
    if item.Name == filename && item.Hash == md5sum {
      if logOption {
        fmt.Println((time.Now()).Format(layout),"| Notice |  Whitelist |",filename)
      } else {
        fmt.Println("\tWhitelist for ",filename)
      }
      return true
    }
  }
  return false
}

func CheckFileText(path string, database Database, vt bool) (bool, string) {

  if len(database.List) == 0 && vt == false {
    return false, ""
  } else if InWhiteList(path) {
    return false, ""
  } else if vt == true {
    return ScanFileOnVt(path)
  }

  f, err := ioutil.ReadFile(path)
  if err != nil {
    if logOption {
      fmt.Println((time.Now()).Format(layout),"| Error | Open File |",path)
    } else {
      fmt.Println(err)
    }
    return false, ""
  }
  f_nolines := string(f)
  var filedata Filedata
  filedata.Name = path
  for _, malware := range database.List {
    founds := 0
    if malware.Status == "enabled" {
      for _, signature := range malware.Signatures {
          re := regexp.MustCompile(signature)
          occ := re.FindStringSubmatch(f_nolines)
           if len(occ) > 0 {
             founds += 1
             filedata.Signature = append(filedata.Signature, FileSignature{ Signature: signature, Text: occ[0]})
             if malware.Method != "and" {
               founds = len(malware.Signatures)
               break
             }
           }
      }
      if founds == len(malware.Signatures) {
            finalReport.Positives += 1
            filedata.Name = path
            filedata.Malware = malware.Name
            finalReport.Files = append(finalReport.Files, filedata)
           return true, malware.Name
      }
    }
  }
  return false, ""
}

func LoadDatabase(extension string) Database {

  var database Database
  switch extension {
  case "php":
    if len(DBSignaturesPHP.List) != 0 {
        return DBSignaturesPHP
    } else {
      //db = & DBSignaturesPHP
    }
  case "js":
    if len(DBSignaturesJS.List) != 0 {
        return DBSignaturesJS
    } else {
      //db = & DBSignaturesPHP
    }
  case "img":
    if len(DBSignaturesIMG.List) != 0 {
        return DBSignaturesIMG
    } else {
      //db = & DBSignaturesPHP
    }
  default:

  }
  if logOption {
    fmt.Println((time.Now()).Format(layout),"| Notice | Loading DB Signatures for",extension,"files")
  } else {
    fmt.Printf("\tLoading DB Signatures for %s files\n",extension)
  }
  if _,err := os.Stat("Signatures/signatures_"+extension+".json"); err == nil {
      cg,_:= ioutil.ReadFile("Signatures/signatures_"+extension+".json")
      //database := Database{}
      _= json.Unmarshal([]byte(cg),&database)
    } else if os.IsNotExist(err) {
      if logOption {
        fmt.Println((time.Now()).Format(layout),"| Alert | Can't find signatures file signatures",extension,".json")
      } else {
        fmt.Println("I can't find signatures_",extension,".json")
      }
    } else {
      if logOption {
        fmt.Println((time.Now()).Format(layout),"| Alert | Something goes wrong")
      } else {
        fmt.Println("Something goes wrong")
        fmt.Println(err)
      }
    }
    return database
}

func ScanFile(file string, vt bool) (bool, string) {
  // var malware string
  // var positive bool

  extension := filepath.Ext(file)
  switch extension {
  case ".php":
    DBSignaturesPHP = LoadDatabase("php")
    return CheckFileText(file,DBSignaturesPHP, vt)
  case ".js":
    DBSignaturesJS = LoadDatabase("js")
    return CheckFileText(file,DBSignaturesJS, vt)
  case ".jpg":
    DBSignaturesIMG = LoadDatabase("img")
    return CheckFileImage(file, DBSignaturesIMG,vt)
  default:
    //positive, malware = CheckFile(file,Database{},vt)
    return CheckFileText(file, Database{}, vt)

  }
  return false,""
}

type walkFunc func(exif.FieldName, *tiff.Tag) error

func (f walkFunc) Walk(name exif.FieldName, tag *tiff.Tag) error {
	return f(name, tag)
}

func CheckFileImage(path string, database Database, vt bool) (bool, string) {
  raw, err := ioutil.ReadFile(path)
  filedata := Filedata{}
	if err != nil {
		fmt.Println(err)
	}
	x, err := exif.Decode(bytes.NewReader(raw))
	if err != nil {
		fmt.Println(err)
	}
  positive := false
  malwareName := ""
  err = x.Walk(walkFunc(func(name exif.FieldName, tag *tiff.Tag) error {
    if positive {
      return nil
    }
    for _, malware := range database.List {
      if malware.Status == "enabled" {
         founds := 0
         for _, signature := range malware.Signatures {
          re := regexp.MustCompile(signature)
           str := fmt.Sprint(tag)
  	       matches := re.FindAllString(str, -1)
  	       if len(matches) > 0 {
             founds += 1
             filedata.Signature = append(filedata.Signature, FileSignature{ Signature: signature, Text: str})
             if malware.Method == "and" {
                if founds == len(malware.Signatures) {
                  finalReport.Positives += 1
                  filedata.Name = path
                  filedata.Malware = malware.Name
                  finalReport.Files = append(finalReport.Files, filedata)
                  positive = true
                  malwareName = malware.Name
                  return nil
                }
             } else {
               filedata.Malware = malware.Name
               filedata.Name = path
               finalReport.Positives += 1
               finalReport.Files = append(finalReport.Files, filedata)
               positive = true
               malwareName = malware.Name
               return nil
             }
           }
         }
       }
     }
		return nil
	}))
  return positive,malwareName
}

func ScanDirectory(path string, vt bool) error {

  if ! logOption {
    fmt.Println("Scanning dir: ",path)
  }
  err := filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
    if !info.IsDir() {
      finalReport.TotalFiles += 1
      infected, malware := ScanFile(file, vt)
      if infected {
        if logOption {
          fmt.Println((time.Now()).Format(layout),"| Warning | File infected |",malware,"|",file)
        } else {
          color.Red("\tWARNING: %s\n",malware)
          color.Blue("\t\tFILE: %s\n",file)
        }
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
    if logOption {
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
          if logOption {
            fmt.Println((time.Now()).Format(layout),"| Event |",event.Op,"|",event.Name)
          }
          infected, malware := ScanFile(event.Name,vt)
          if infected {
            if logOption {
              fmt.Println((time.Now()).Format(layout),"| Warning | File infected |",malware,"|",path)
            } else {
              color.Green("\tEvent: %s\n",event.Op)
              color.Red("\tWARNING: %s\n",malware)
              color.Blue("\tFILE: %s\n",event.Name)
              if telegramOption {
                SendTelegramAlert("WARNING", event.Name, malware)
              }
            }
          }
        }

				// watch for errors
			case err := <-watcher.Errors:
        if logOption {
          fmt.Println((time.Now()).Format(layout)," |Error | Read Directory")
        } else {
				  fmt.Println("ERROR", err)
        }
			}
		}
	}()

	<-done
}

func SaveReport(report FinalReport) {
  fmt.Println("Save Report")

  file,_ := json.MarshalIndent(report,""," ")
  _ = ioutil.WriteFile("LastReport.json",file,0644)

}

func main() {
  scanCmd := flag.NewFlagSet("scan",flag.ExitOnError)
  monitorCmd := flag.NewFlagSet("monitor",flag.ExitOnError)

  if len(os.Args) < 3 {
    fmt.Println("expected scan or monitor parameter.")
    fmt.Printf("\twebsite_scan scan -path/var/www/html\n")
    fmt.Printf("\twebsite_scan monitor -path=/var/www/html -vt -log\n")
  } else {
      LoadWhitelist()
      LoadTelegramUsers()
      finalReport.Date = (time.Now()).Format(layout)
      switch os.Args[1] {
      case "scan":
        path := scanCmd.String("path","","path to the directory")
        vt := scanCmd.Bool("vt",false,"virus total option")
        out := scanCmd.Bool("log",false,"Output Option")
        tel := scanCmd.Bool("telegram",false,"Output Option")

        scanCmd.Parse(os.Args[2:])
        logOption = *out
        telegramOption = *tel
        finalReport.Path = *path
        if logOption {
          fmt.Println((time.Now()).Format(layout),"| Notice | Start Scan |",*path)
        } else {
            fmt.Println("Starting scanning")
        }
        ScanDirectory(*path,*vt)
        if logOption {
          fmt.Println((time.Now()).Format(layout),"| Notice | End Scan |", finalReport.TotalFiles,"|", finalReport.Positives)
        } else {
          fmt.Println("End Scan")
          fmt.Println("Total Files Scanned: ",finalReport.TotalFiles)
          fmt.Println("Total Positives:     ",finalReport.Positives)
          if telegramOption {
            SendSummaryReport()
          }
          SaveReport(finalReport)
        }
      case "monitor":
        path := monitorCmd.String("path","","path to the directory")
        vt := monitorCmd.Bool("vt",false,"virus total option")
        out := monitorCmd.Bool("log",false,"Output Option")
        tel := monitorCmd.Bool("telegram",false,"Output Option")

        monitorCmd.Parse(os.Args[2:])
        logOption = *out
        telegramOption = *tel
        if logOption {
          fmt.Println((time.Now()).Format(layout),"| Notice | Start Monitor |",*path)
        } else {
            fmt.Println("Start Monitor")
        }
        MonitoringDirectory(*path,*vt)
      default:
        fmt.Println("There are scan or monitor option")

      }
  }
  return
}
