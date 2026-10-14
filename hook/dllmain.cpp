#include "pch.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <locale>
#include <codecvt>

#define BUFFER_SIZE 1024
#define SIZE 11 
#define hideSIZE 11

extern "C" LPVOID trampoline = nullptr; // адрес трамплина
BYTE oldBytes[SIZE] = { 0 };            // оригинальные байты функции
BYTE oldBytesHIDE[hideSIZE];            // оригинальные байты функции для скрытия
DWORD oldProtect = 0;                   // старые права доступа к памяти

// типы функций для перехвата
typedef HANDLE(WINAPI* FindFirstFileW_t)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef BOOL(WINAPI* FindNextFileW_t)(HANDLE, LPWIN32_FIND_DATAW);
typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

// указатели на оригинальные функции
FindFirstFileW_t RealFindFirstFileW = nullptr;
FindNextFileW_t RealFindNextFileW = nullptr;
CreateFileW_t RealCreateFileW = nullptr;

// указатели на перехваченные функции
FindFirstFileW_t HookedFindFirstFileW = nullptr;
FindNextFileW_t HookedFindNextFileW = nullptr;
CreateFileW_t HookedCreateFileW = nullptr;

extern "C" void hook_handler();    // ассемблерная функция для установки перехвата
extern "C" LPVOID Target = NULL;   // адрес целевой функции для перехвата

std::string HiddenFile;        // путь к скрываемому файлу в виде std::string
std::wstring wHiddenFile;      // путь к скрываемому файлу в виде std::wstring
HANDLE PipeHandle;             // дескриптор именованного канала
CHAR Function[BUFFER_SIZE];    // название функции для перехвата

// запись в именованный канал
bool WriteToPipe(HANDLE pipeHandle, const char* message) {
    if (pipeHandle == INVALID_HANDLE_VALUE || message == nullptr) {
        return false;
    }

    DWORD countWriteBytes = (DWORD)(strlen(message) + 1);
    DWORD countWrittenBytes = 0;

    // запись в именованный канал
    BOOL result = WriteFile(pipeHandle, message, countWriteBytes, &countWrittenBytes, NULL);

    return (result != 0 && countWrittenBytes == countWriteBytes);
}

// чтение из именованного канала
bool ReadFromPipe(HANDLE pipeHandle, char* buffer, DWORD bufferSize, DWORD* bytesRead) {
    if (pipeHandle == INVALID_HANDLE_VALUE || buffer == nullptr || bytesRead == nullptr || bufferSize == 0) {
        return false;
    }
    ZeroMemory(buffer, bufferSize);

	// читаем из именованного канала
    BOOL result = ReadFile(pipeHandle, buffer, bufferSize - 1, bytesRead, NULL);

    return (result != 0 && *bytesRead > 0);
}

// создание и подключение к именованному каналу
bool connectPipe(HANDLE* PipeHandle) {
    LPCTSTR PipeName = TEXT("\\\\.\\pipe\\monitor");
    DWORD Mode;
    BOOL result;

    while (true) {
        *PipeHandle = CreateFile(PipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        // Успешное подключение
        if (*PipeHandle != INVALID_HANDLE_VALUE) {
            break;
        }

        DWORD error = GetLastError();
        if (error == ERROR_PIPE_BUSY) {
            if (!WaitNamedPipe(PipeName, 20000)) return false;
        }
        else if (error == ERROR_FILE_NOT_FOUND) {
            Sleep(1000);
            continue;
        }
        else {
            return false;
        }
    }

    // Устанавливаем режим чтения сообщений
    Mode = PIPE_READMODE_MESSAGE;
    result = SetNamedPipeHandleState(*PipeHandle, &Mode, NULL, NULL);

    if (!result) {
        CloseHandle(*PipeHandle);
        return false;
    }
    return true;
}

// Вызывается ассемблерным hook_handler при каждом вызове мониторимой функции
extern "C" void Status() {
    static char Timer[16] = "";
    CHAR MessageToSend[BUFFER_SIZE];
    SYSTEMTIME SysTime;
    GetLocalTime(&SysTime);

    CHAR CurrentTime[16];
    sprintf_s(CurrentTime, "%02d:%02d:%02d", SysTime.wHour, SysTime.wMinute, SysTime.wSecond);

    // Проверяем изменение времени
    if (strcmp(CurrentTime, Timer) != 0) {
        strcpy_s(Timer, 16, CurrentTime); // Просто копируем новое время
        sprintf_s(MessageToSend, "[F] %s()\tin time: %s", Function, Timer);
        WriteToPipe(PipeHandle, MessageToSend);
    }
}

// Перехваченная FindFirstFileW
HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
    using Fn = HANDLE(WINAPI*)(LPCWSTR, LPWIN32_FIND_DATAW);
    HANDLE result = ((Fn)HookedFindFirstFileW)(lpFileName, lpFindFileData);

    if (result != INVALID_HANDLE_VALUE && wHiddenFile == lpFileName) {
        return INVALID_HANDLE_VALUE; // Скрываем файл
    }

    return result;
}

// Перехваченная FindNextFileW
BOOL WINAPI MyFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
    using Fn = BOOL(WINAPI*)(HANDLE, LPWIN32_FIND_DATAW);
    BOOL result = ((Fn)HookedFindNextFileW)(hFindFile, lpFindFileData);

    if (result && wHiddenFile == lpFindFileData->cFileName) {
        return FALSE; // Скрываем файл
    }

    return result;
}

// Перехваченная CreateFileW
HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    using Fn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    HANDLE result = ((Fn)HookedCreateFileW)(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    if (wHiddenFile == lpFileName) {
        return INVALID_HANDLE_VALUE; // Скрываем файл
    }

    return result;
}

// Функция для изменения целевой функции на новую
bool changeFunction(LPVOID Target, LPVOID newFunction) {
    // Вычисляем относительное смещение
    // Если Target находится по 0x1000, а newFunction по 0x2000, то:
    // JMPSize = (0x2000 - 0x1000 - 5) = 0x0FFB
    DWORD_PTR JMPSize = ((DWORD_PTR)newFunction - ((DWORD_PTR)Target + 5));

    // Открываем доступ к памяти
    // Функция VirtualProtect изменяет права доступа к памяти.
    // Оригинальный код находится в памяти только для чтения(PAGE_EXECUTE_READ).
    // Мы меняем его на PAGE_EXECUTE_READWRITE, чтобы записать туда JMP.
    if (!VirtualProtect(Target, SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::wcerr << L"[-] Failed to change memory protection." << std::endl;
        return false;
    }

    // Запоминаем старые байты
    memcpy(oldBytes, Target, SIZE);

    // Патчим оригинал: JMP + NOPs
    BYTE tempJMP[SIZE] = { 0 };
    tempJMP[0] = 0xE9;
    memcpy(&tempJMP[1], &JMPSize, 4);
    memset(&tempJMP[5], 0x90, SIZE - 5);  // NOP
    WriteProcessMemory(GetCurrentProcess(), Target, tempJMP, SIZE, nullptr);
    FlushInstructionCache(GetCurrentProcess(), Target, SIZE);

    // === ТРАМПЛИН ===
    trampoline = VirtualAlloc(NULL, SIZE + 8, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) {
        std::wcerr << L"[-] VirtualAlloc failed for trampoline." << std::endl;
        VirtualProtect(Target, SIZE, oldProtect, &oldProtect);
        return false;
    }

    //Делаем патч в трамплине на потерянные байты + JMP в kernelbase+size
    memcpy(trampoline, oldBytes, SIZE);
    BYTE* jmpIAT = (BYTE*)trampoline + SIZE;
    jmpIAT[0] = 0xFF;
    jmpIAT[1] = 0x25;
    memset(&jmpIAT[2], 0, 4);
    DWORD_PTR NewTarget = (DWORD_PTR)Target + SIZE;
    memcpy(&jmpIAT[6], &NewTarget, 8);

    //ставим защиту обратно
    VirtualProtect(Target, SIZE, oldProtect, &oldProtect);
    return true;
}

bool changeFunctionHOOKS(LPVOID Target, LPVOID newFunction, LPVOID* WhereToTrampoline) {
    // Вычисляем относительное смещение
    // Если Target находится по 0x1000, а newFunction по 0x2000, то:
    // JMPSize = (0x2000 - 0x1000 - 5) = 0x0FFB
    DWORD_PTR JMPSize = ((DWORD_PTR)newFunction - ((DWORD_PTR)Target + 5));

    // Открываем доступ к памяти
    // Функция VirtualProtect изменяет права доступа к памяти.
    // Оригинальный код находится в памяти только для чтения(PAGE_EXECUTE_READ).
    // Мы меняем его на PAGE_EXECUTE_READWRITE, чтобы записать туда JMP.
    if (!VirtualProtect(Target, hideSIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::wcerr << L"[-] Failed to change memory protection." << std::endl;
        return false;
    }

    // Запоминаем старые байты
    memcpy(oldBytesHIDE, Target, hideSIZE);

    // Патчим оригинал: JMP + NOPs
    BYTE tempJMP[hideSIZE] = { 0 };
    tempJMP[0] = 0xE9;
    memcpy(&tempJMP[1], &JMPSize, 4);
    memset(&tempJMP[5], 0x90, hideSIZE - 5);  // NOP

    if (!WriteProcessMemory(GetCurrentProcess(), Target, tempJMP, hideSIZE, nullptr)) {
        std::wcerr << L"[-] WriteProcessMemory failed. Error: " << GetLastError() << std::endl;
        VirtualProtect(Target, hideSIZE, oldProtect, &oldProtect);
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), Target, hideSIZE);

    // === ТРАМПЛИН ===
    trampoline = VirtualAlloc(NULL, hideSIZE + 8, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) {
        std::wcerr << L"[-] VirtualAlloc failed for trampoline." << std::endl;
        VirtualProtect(Target, hideSIZE, oldProtect, &oldProtect);
        return false;
    }

    //Делаем патч в трамплине на потерянные байты + JMP в kernelbase+size
    memcpy(trampoline, oldBytesHIDE, hideSIZE);
    BYTE* jmpIAT = (BYTE*)trampoline + hideSIZE;
    jmpIAT[0] = 0xFF;
    jmpIAT[1] = 0x25;
    memset(&jmpIAT[2], 0, 4);
    DWORD_PTR NewTarget = (DWORD_PTR)Target + hideSIZE;
    memcpy(&jmpIAT[6], &NewTarget, 8);

    //ставим защиту обратно
    VirtualProtect(Target, hideSIZE, oldProtect, &oldProtect);
    *WhereToTrampoline = trampoline;
    return true;
}

// Установка хуков для скрытия файла
bool SetHooksHideFile(const std::string& fileName) {
    HiddenFile = fileName;
    // Преобразование в wstring
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> converter;
    wHiddenFile = converter.from_bytes(HiddenFile);

    if (changeFunctionHOOKS(RealFindFirstFileW, MyFindFirstFileW, (LPVOID*)&HookedFindFirstFileW) != true) return false;
    if (changeFunctionHOOKS(RealFindNextFileW, MyFindNextFileW, (LPVOID*)&HookedFindNextFileW) != true) return false;
    if (changeFunctionHOOKS(RealCreateFileW, MyCreateFileW, (LPVOID*)&HookedCreateFileW) != true) return false;
    return true;
}

// Поток для инициализации хуков и общения с именованным каналом
DWORD WINAPI InitThread(LPVOID lpParam) {
    Sleep(200);
    CHAR Command[BUFFER_SIZE];
    CHAR PathFile[BUFFER_SIZE];
    static bool Listening = true;
    bool result = false;

    //HANDLE PipeHandle;
    CHAR MessageBuff[BUFFER_SIZE];	    // Отправить/получить сообщение к Monitor
    DWORD bytesRead;					// Сколько байт получено
    if (connectPipe(&PipeHandle)) {
        while (Listening) {
            // 1. Читаем первую команду (-func или -hide)
            if (!ReadFromPipe(PipeHandle, MessageBuff, BUFFER_SIZE, &bytesRead)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) {
                    CloseHandle(PipeHandle);
                    if (!connectPipe(&PipeHandle)) {
                        return -1;
                    }
                }
                continue;
            }

            // 2. Определяем тип команды
            if (strcmp(MessageBuff, "-func") == 0) {
                strcpy_s(Command, MessageBuff);
                WriteToPipe(PipeHandle, "[OK] Waiting for function name.");

                // 3. Ждем имя функции
                if (!ReadFromPipe(PipeHandle, MessageBuff, BUFFER_SIZE, &bytesRead)) {
                    WriteToPipe(PipeHandle, "[ERROR] No function name received.");
                    continue;
                }
                strcpy_s(Function, MessageBuff);

                //// 4. Хукаем
                HMODULE hModule = GetModuleHandleW(L"kernelbase.dll");
                if (hModule == NULL) {
                    WriteToPipe(PipeHandle, "[ERROR] Failed to get module handle for kernelbase.dll");
                    return FALSE;
                }
                Target = (DWORD*)GetProcAddress(hModule, Function);
                if (Target != NULL) {
                    result = changeFunction(Target, hook_handler);
                }
                if (result == true) {
                    WriteToPipe(PipeHandle, "[OK] Function hooked.");
                    Listening = false;
                } else {
                    WriteToPipe(PipeHandle, "[ERROR] Failed to hook function.");
                    return FALSE;
                }
            } else if (strcmp(MessageBuff, "-hide") == 0) {
                strcpy_s(Command, MessageBuff);
                WriteToPipe(PipeHandle, "[OK] Waiting for file path.");

                // 3. Ждем путь к файлу
                if (!ReadFromPipe(PipeHandle, MessageBuff, BUFFER_SIZE, &bytesRead)) {
                    WriteToPipe(PipeHandle, "[ERROR] No file path received.");
                    continue;
                }
                strcpy_s(PathFile, MessageBuff);

                HMODULE hModule = GetModuleHandleW(L"kernelbase.dll");
                if (hModule == NULL) {
                    WriteToPipe(PipeHandle, "[ERROR] Failed to get module handle for kernelbase.dll");
                    return FALSE;
                }
                RealFindFirstFileW = (FindFirstFileW_t)GetProcAddress(hModule, "FindFirstFileW");
                RealFindNextFileW = (FindNextFileW_t)GetProcAddress(hModule, "FindNextFileW");
                RealCreateFileW = (CreateFileW_t)GetProcAddress(hModule, "CreateFileW");

                result = SetHooksHideFile(PathFile);
                if (result == true) {
                    WriteToPipe(PipeHandle, "[OK] File hidden.");
                    Listening = false;
                } else {
                    WriteToPipe(PipeHandle, "[ERROR] Failed to hide file.");
                    return FALSE;
                }
            } else {
                WriteToPipe(PipeHandle, "[ERROR] Unknown command.");
            }
        }
    }
    return 0;
}

// Точка входа DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}