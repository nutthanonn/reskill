package utils

import (
	"fmt"

	"github.com/fatih/color"
)

func Information(str string) {
	var blue = color.New(color.FgBlue).SprintFunc()
	formattedString := fmt.Sprintf("[%s] %s", blue("INF"), str)

	fmt.Println(formattedString)
}

func Success(str string) {
	var green = color.New(color.FgGreen).SprintFunc()
	formattedString := fmt.Sprintf("[%s] %s", green("OK"), str)

	fmt.Println(formattedString)
}

func Error(str string) {
	var red = color.New(color.FgRed).SprintFunc()
	formattedString := fmt.Sprintf("[%s] %s", red("ERR"), str)

	fmt.Println(formattedString)
}
