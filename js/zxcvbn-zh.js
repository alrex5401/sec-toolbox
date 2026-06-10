/*
 * zxcvbn-ts 繁體中文 translations（key 結構對齊 @zxcvbn-ts/language-en 3.x）
 * 自譯、供本站使用。
 */
(function (global) {
  "use strict";

  global.zxcvbnZhTW = {
    warnings: {
      straightRow: "鍵盤上一整排相鄰的按鍵、很容易被猜到。",
      keyPattern: "短的鍵盤路徑模式、很容易被猜到。",
      simpleRepeat: "重複字元（像「aaa」）很容易被猜到。",
      extendedRepeat: "重複的字元模式（像「abcabcabc」）很容易被猜到。",
      sequences: "常見的連續字元（像「abc」「123」）很容易被猜到。",
      recentYears: "近代年份很容易被猜到。",
      dates: "日期很容易被猜到。",
      topTen: "這是被大量使用的密碼（前 10 名等級）。",
      topHundred: "這是非常常見的密碼（前 100 名等級）。",
      common: "這是常見密碼。",
      similarToCommon: "這和常見密碼非常相似。",
      wordByItself: "單一一個單字很容易被猜到。",
      namesByThemselves: "單獨的名字或姓氏很容易被猜到。",
      commonNames: "常見的名字和姓氏很容易被猜到。",
      userInputs: "密碼不應包含個人相關或與此網站相關的資料。",
      pwned: "這個密碼曾在網路上的資料外洩事件中被公開過。"
    },
    suggestions: {
      l33t: "避免可預測的字元替換、例如用「@」代替「a」。",
      reverseWords: "避免把常見單字倒過來拼。",
      allUppercase: "大寫部分字母就好、不要全部大寫。",
      capitalization: "不要只大寫第一個字母。",
      dates: "避免使用和你有關的日期與年份。",
      recentYears: "避免使用近代年份。",
      associatedYears: "避免使用和你有關的年份。",
      sequences: "避免常見的連續字元。",
      repeated: "避免重複的單字和字元。",
      longerKeyboardPattern: "使用更長的鍵盤路徑、並多次改變打字方向。",
      anotherWord: "再加幾個比較少見的單字。",
      useWords: "使用多個單字組合、但避免常見片語。",
      noNeed: "不靠符號、數字或大寫字母、也能建立強密碼。",
      pwned: "如果你在其他地方也用這個密碼、應該立刻更換。"
    },
    timeEstimation: {
      ltSecond: "不到一秒",
      second: "{base} 秒",
      seconds: "{base} 秒",
      minute: "{base} 分鐘",
      minutes: "{base} 分鐘",
      hour: "{base} 小時",
      hours: "{base} 小時",
      day: "{base} 天",
      days: "{base} 天",
      month: "{base} 個月",
      months: "{base} 個月",
      year: "{base} 年",
      years: "{base} 年",
      centuries: "數百年以上"
    }
  };
})(window);
