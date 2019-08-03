package main

import (
	"fmt"
	"log"
	"strings"
	"os"
	"io/ioutil"
	"regexp"
	"encoding/json"
	"strconv"
	"bufio"
	"github.com/go-telegram-bot-api/telegram-bot-api"
)

const telegramKey = "teste" //this is the passphare that users need send to register (/monitor passphase)
const ruleNewUser = "\\/monitor [A-Za-z0-9]*\\z"
const ruleShowReport	= "/lastreport"
const APIKEY = ""

type FileSignature struct {
  Signature string `json:"Signature"`
  Text      string `json:"Text"`
}

type Filedata struct {
  Name      string  `json:"Filename"`
  Malware   string  `json:"Malware_Name"`
  Signature []FileSignature `json:"Description"`
}

type FinalReport struct {
  Path        string      `json:"Path"`
  TotalFiles  int64       `json:"Total"`
  Positives   int64       `json:"Positives"`
  Date        string      `json:"Date"`
  Files       []Filedata  `json:"Infected_Files"`
}


func NewUser(idUser int) {

	if ! CheckUserPermission(idUser) {
		fmt.Println("Register New User:",strconv.Itoa(idUser))
		file, err := os.OpenFile(
        "telegram.users",
        os.O_APPEND|os.O_WRONLY|os.O_CREATE,
        0666,
    )
    if err != nil {
        fmt.Println(err)
    }
    defer file.Close()

    // Write bytes to file
    byteSlice := []byte(strconv.Itoa(idUser)+"\n")
    _, err = file.Write(byteSlice)
    if err != nil {
        fmt.Println(err)
    }
    //log.Printf("Wrote %d bytes.\n", bytesWritten)
	}

}

func SendLastReport(bot *tgbotapi.BotAPI, chatID int64) {
	var lastreport FinalReport
	if _,err := os.Stat("LastReport.json"); err == nil {
			fmt.Println("Sending Last Report user ",chatID)
      cg,_:= ioutil.ReadFile("lastreport.json")
      _= json.Unmarshal([]byte(cg),&lastreport)
			message := "<b>LAST REPORT</b>\n"

			for _,file := range lastreport.Files {
					//telegram API limit message size 4096
					if (len(message)+len(file.Name)+len(file.Malware)) > 4000  {
							fmt.Println(message)
							msg := tgbotapi.NewMessage(chatID, message)
							msg.ParseMode = "html"
							bot.Send(msg)
							message = ""
					}
					message += "<b>File:</b> <i>"+file.Name+"</i>\n"
					message += "<b>Malware:</b><i>"+file.Malware+"</i>\n"
			}
			// if len(message) > 0  {
			// 	fmt.Println("SEND MESSAGE to:",chatID)
			// 	fmt.Println(message)
			// 		msg := tgbotapi.NewMessage(chatID, message)
			// 		msg.ParseMode = "html"
			// 		bot.Send(msg)
			// }
			message += "<b>END</b>"
			msg := tgbotapi.NewMessage(chatID, message)
			msg.ParseMode = "html"
			bot.Send(msg)
    } else if os.IsNotExist(err) {
        fmt.Println("There isn't Whitelist file")
    } else {
        fmt.Println("Something goes wrong")
        fmt.Println(err)
    }
}

func CheckUserPermission(userID int) bool {
	fd, err := os.Open("telegram.users")
  if err != nil {
        return false
  }
  defer fd.Close()

  if err != nil {
    return false
  }
  scanner := bufio.NewScanner(fd)
  scanner.Split(bufio.ScanWords)
  for scanner.Scan() {
        x, _ := strconv.Atoi(scanner.Text())
        if userID == x {
					fmt.Println("User ",userID," Autorized")
					return true
				}
    }
	fmt.Println("User ",userID,"Not Autorized")
	return false
}

func main() {
	bot, err := tgbotapi.NewBotAPI(APIKEY)
	if err != nil {
		log.Panic(err)
	}

	bot.Debug = false

	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates, err := bot.GetUpdatesChan(u)
	//var chatid int64

	for update := range updates {
		if update.Message == nil { // ignore any non-Message Updates
			continue
		}
		//Check New User
		re := regexp.MustCompile(ruleNewUser)
		result := re.FindStringSubmatch(update.Message.Text)
		if len(result) > 0 {
				text := strings.Fields(result[0])
				if text[0] == "/monitor" && text[1] == telegramKey {
					NewUser(int(update.Message.Chat.ID))
					//fmt.Println(update.Message.Chat.ID)
					//chatid = update.Message.Chat.ID
					//break
				}
		}

		re = regexp.MustCompile(ruleShowReport)
		result = re.FindStringSubmatch(update.Message.Text)
		if len(result) > 0 {
				//teste := strings.Fields(result[0])
				if CheckUserPermission(int(update.Message.Chat.ID)) {
					SendLastReport(bot, update.Message.Chat.ID)
				}
		}


		//msg := tgbotapi.NewMessage(update.Message.Chat.ID, update.Message.Text)
		//msg.ReplyToMessageID = update.Message.MessageID

		//bot.Send(msg)
	}
	//msg := tgbotapi.NewMessage(chatid, "OK")
	//bot.Send(msg)
}
