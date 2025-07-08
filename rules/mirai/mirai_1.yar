rule malware_mirai_1: malware {
  meta:
    author_malvare_1 = "Anna-Senpai"  // публичный псевдоним, использовался при публикации исходного кода
    author_malvare_2 = "Josiah White"  // один из реальных разработчиков
    author_malvare_3 = "Paras Jha"  // совместно создал ботнет
    author_malvare_4 = "Cody Cornell"  // третий участник команды (некоторые источники указывают его как одного из авторов)

    author_research_1 = "Brian Krebs"  // первый публично сообщил о Mirai после DDoS -атаки на свой сайт
    author_research_2 = "Artem Kozlyuk"  // исследователь Flashpoint
    author_research_3 = "Robert Simmons"  // исследователь Flashpoint
    author_research_4 = "Jeff Brown"  // исследователь Flashpoint
    author_research_5 = "Lumen Technologies (Level 3)"  // компания, опубликовавшая технический анализ
    author_research_6 = "FBI"  // установило личности реальных авторов
    author_research_7 = "Daniel Cuthbert"  // SANS Institute, аналитик по IoT -угрозам
    author_research_8 = "Kevin Beaumont"  // независимый исследователь безопасности

    description = "Detects Mirai botnet malware components"
    reference   = "https://github.com/jgamblin/Mirai-Source-Code "  // исходный код, опубликованный Anna-Senpai

  strings:
    // Полные URL-пути
    $http_mirai_arm7 = "GET /bins/mirai.arm7 HTTP/1.0" ascii wide
    $http_mirai_x86  = "GET /bins/mirai.x86 HTTP/1.0" ascii wide
    $http_mirai_mips = "GET /bins/mirai.mips HTTP/1.0" ascii wide
    $http_mirai_ppc  = "GET /bins/mirai.ppc HTTP/1.0" ascii wide
    $http_mirai_sh4  = "GET /bins/mirai.sh4 HTTP/1.0" ascii wide
    $http_mirai_m68k = "GET /bins/mirai.m68k HTTP/1.0" ascii wide

    // Повторяющиеся паттерны
    $pattern_1 = "N^NuNV" ascii wide
    $pattern_3 = "dvrHelper" ascii wide

    $word_1 = "GET /bins/mirai"
    $word_2 = "dvrHelper"

  condition:
    vigilantx_file_detect_magic_ELF and any of them
}

rule malware_mirai_b: malware {
  meta:
    author_malvare_1 = "Anna-Senpai"  // публичный псевдоним, использовался при публикации исходного кода
    author_malvare_2 = "Josiah White"  // один из реальных разработчиков
    author_malvare_3 = "Paras Jha"  // совместно создал ботнет
    author_malvare_4 = "Cody Cornell"  // третий участник команды (некоторые источники указывают его как одного из авторов)

    author_research_1 = "Brian Krebs"  // первый публично сообщил о Mirai после DDoS -атаки на свой сайт
    author_research_2 = "Artem Kozlyuk"  // исследователь Flashpoint
    author_research_3 = "Robert Simmons"  // исследователь Flashpoint
    author_research_4 = "Jeff Brown"  // исследователь Flashpoint
    author_research_5 = "Lumen Technologies (Level 3)"  // компания, опубликовавшая технический анализ
    author_research_6 = "FBI"  // установило личности реальных авторов
    author_research_7 = "Daniel Cuthbert"  // SANS Institute, аналитик по IoT -угрозам
    author_research_8 = "Kevin Beaumont"  // независимый исследователь безопасности

    description = "Detects Mirai botnet malware components"
    reference   = "https://github.com/jgamblin/Mirai-Source-Code "  // исходный код, опубликованный Anna-Senpai

  strings:
    $word_0  = "79.124.8.24/bins/sora"
    $word_1  = "dotheneedfull.xyz/fetch"
    $word_2  = "46.239.223.80"
    $word_3  = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv7l/bin/../cc/include"
    $word_4  = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc"
    $word_5  = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm"
    $word_6  = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S"
    $word_7  = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm"
    $word_8  = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S"
    $word_9  = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c"
    $word_10 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c"

  condition:
    any of them
}
