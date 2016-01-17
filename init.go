package sleepwalker

import "github.com/Sirupsen/logrus"

var APIRoot string

func init() {
	Log = logrus.New()
}
