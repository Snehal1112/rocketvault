package common

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/sirupsen/logrus"
	"golang.org/x/text/language"
)

var locales = make(map[string]string)
var localizer = &i18n.Localizer{}

// TODO: to manage the multiple language stuff. implement as follow
// - create bundler manager
// - create bundle for each language
// - register bundle to bindler manager
// - create get function. which return the bundle based on lang code.
var bundle = &i18n.Bundle{}

// TranslationsPreInit func
func TranslationsPreInit() error {
	var code string = "ja"
	tag, err := language.Parse(code)
	if err != nil {
		// TODO: user loguras to log the error.
		log.Println("Unable to parse the language code :", code)
	}

	lang, err := language.Compose(tag)
	if err != nil {
		log.Println("Unable to compose the language : ", lang)
		return err
	}

	bundle = i18n.NewBundle(lang)

	if err := InitTranslationsWithDir("i18n"); err != nil {
		return err
	}

	localizer = i18n.NewLocalizer(bundle, code)

	return nil
}

// InitTranslationsWithDir func
func InitTranslationsWithDir(dir string) error {
	i18nDirectory, found := FindDir(dir)
	if !found {
		return fmt.Errorf("Unable to find i18n directory")
	}

	files, _ := os.ReadDir(i18nDirectory)
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".json" {
			filename := f.Name()
			locales[strings.Split(filename, ".")[0]] = i18nDirectory + filename

			if _, err := bundle.LoadMessageFile(i18nDirectory + filename); err != nil {
				return err
			}
		}
	}

	return nil
}

// FindDir func
func FindDir(dir string) (string, bool) {
	fileName := "."
	found := false

	if _, err := os.Stat("./" + dir + "/"); err == nil {
		fileName, _ = filepath.Abs("./" + dir + "/")
		found = true
	} else if _, err := os.Stat("../" + dir + "/"); err == nil {
		fileName, _ = filepath.Abs("../" + dir + "/")
		found = true
	} else if _, err := os.Stat("../../" + dir + "/"); err == nil {
		fileName, _ = filepath.Abs("../../" + dir + "/")
		found = true
	}

	return fileName + "/", found
}

// T func
func T(translationID string, args ...interface{}) string {
	localizeCfg := &i18n.LocalizeConfig{
		MessageID: translationID,
		DefaultMessage: &i18n.Message{
			ID: translationID,
		},
	}

	if len(args) > 0 {
		localizeCfg.TemplateData = args[0]
	}

	msg, err := localizer.Localize(localizeCfg)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"translationID": translationID,
		}).Errorln("Error localizing message:", err)
		return ""
	}
	return msg
}
