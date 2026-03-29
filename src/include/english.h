#ifndef ENGLISH_H
#define ENGLISH_H

/**
 * BIP-0039 英文助记词词库
 * 该列表包含 2048 个单词，用于生成确定性钱包的种子。
 */

// 词库大小常量
#define WORDLIST_SIZE 2048

// 声明在 english.c 中定义的全局词库变量
extern const char *WORDLIST[WORDLIST_SIZE];

#endif // ENGLISH_H
