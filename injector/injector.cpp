#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>  // For working with processes

#define BUFFER_SIZE 1024

// отправка в именованный канал
bool WriteToPipe(HANDLE pipeHandle, const char* message) {
    if (pipeHandle == INVALID_HANDLE_VALUE || message == nullptr) {
        return false;
    }

    DWORD countWriteBytes = (DWORD)(strlen(message) + 1); // размер сообщения (+1 для `\0`)
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

    ZeroMemory(buffer, bufferSize); // очистка буфера перед чтением

    // читаем из именованного канала
    BOOL result = ReadFile(pipeHandle, buffer, bufferSize - 1, bytesRead, NULL);

    return (result != 0 && *bytesRead > 0);
}

// создание и подключение к именованному каналу
bool ConnectPipe(HANDLE* hPipe, LPCTSTR nPipe) {
    std::wcout << L"Pay attention!\nIf the program is running with administrator rights, "
        L"then the attacking program needs to be run as administrator too, "
        L"and vice versa with non-administrator." << std::endl;

    // создаём именованный канал в синхронном режиме
    *hPipe = CreateNamedPipe(
        nPipe,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
        PIPE_UNLIMITED_INSTANCES,
        BUFFER_SIZE, BUFFER_SIZE,
        0, NULL);

    if (*hPipe == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] CreateNamedPipe failed, error: " << GetLastError() << std::endl;
        return false;
    }

    std::wcout << L"[*] Pipe created: " << nPipe << std::endl;
    std::wcout << L"[*] Waiting for client to connect..." << std::endl;

    // синхронное ожидание подключения — блокирует поток до подключения клиента
    if (!ConnectNamedPipe(*hPipe, NULL)) {
        DWORD error = GetLastError();
        if (error != ERROR_PIPE_CONNECTED) {
            std::wcerr << L"[-] ConnectNamedPipe failed, error: " << error << std::endl;
            CloseHandle(*hPipe);
            return false;
        }
        // ERROR_PIPE_CONNECTED — клиент уже подключён, это не ошибка
    }

    std::wcout << L"[+] Client connected to Pipe!" << std::endl;
    return true;
}

// существует ли процесс
bool IsProcessRunning(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == nullptr) {
        return false;
    }
    CloseHandle(hProcess);
    return true;
}

bool InjectDLL(DWORD pid, wchar_t* dllPath) {
	HANDLE hProcess;             // дескриптор процесса
	LPVOID pLoadLibrary;         // указатель на функцию LoadLibraryW
	LPVOID pRemoteDllPath;       // указатель на путь к DLL в памяти процесса
	HANDLE hThread;              // дескриптор потока
	wchar_t fullPath[MAX_PATH];  // полный путь к DLL
	wchar_t* lastSlash;          // указатель на последний слэш в пути к исполняемому файлу
	wchar_t exePath[MAX_PATH];   // путь к исполняемому файлу
	wchar_t exeDir[MAX_PATH];    // директория исполняемого файла

    // открываем процесс
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"[-] Failed to open process (PID: " << pid << L"). Error code: " << GetLastError() << std::endl;
        return false;
    }

    // получаем путь к исполняемому файлу
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0) {
        std::wcerr << L"[-] Failed to get executable path. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    std::wcout << L"[DEBUG] Provided DLL Path: " << dllPath << std::endl;
    std::wcout << L"[DEBUG] Executable Path: " << exePath << std::endl;

    // извлекаем директорию из пути к исполняемому файлу
    wcsncpy_s(exeDir, exePath, MAX_PATH);

    // явно удостоверимся, что строка завершается нулем
    exeDir[MAX_PATH - 1] = L'\0';
    lastSlash = wcsrchr(exeDir, L'\\');     // Функция будет искать последний символ \\ в строке exeDir.
    if (lastSlash != nullptr) {
        lastSlash++; // Переходим на следующий символ после \\, чтобы получить имя исполняемого файла
        *lastSlash = L'\0'; // Убираем имя исполняемого файла, оставляем только путь к директории
    } else {
        std::wcerr << L"[-] Failed to extract executable directory." << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    std::wcout << L"[DEBUG] Executable Dir: " << exeDir << std::endl;

    // проверка пути к DLL
    if (dllPath[1] == L':') {
        // путь начинается с диска (C:, D: и т.д.), используем его
        wcscpy_s(fullPath, MAX_PATH, dllPath);
    } else {
        // если путь абсолютный, то просто используем его
        wcscpy_s(fullPath, exeDir);
        wcscat_s(fullPath, MAX_PATH, dllPath);  // объединяем путь с рабочей директорией
    }
    std::wcout << L"[DEBUG] FULL PATH: " << fullPath << std::endl;

    // проверка существования DLL
    FILE* file = nullptr;
    if (_wfopen_s(&file, fullPath, L"rb") != 0 || file == nullptr) {
        std::wcerr << L"[-] DLL does not exist at: " << fullPath << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    fclose(file);

    // получаем адрес LoadLibraryW
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        std::wcerr << L"[-] Failed to get handle of kernel32.dll. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) {
        std::wcerr << L"[-] Failed to get address of LoadLibraryW. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // выделяем память в целевом процессе
    pRemoteDllPath = VirtualAllocEx(hProcess, nullptr, (wcslen(fullPath) + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteDllPath) {
        std::wcerr << L"[-] Memory allocation failed for DLL path. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // записываем путь к DLL в память процесса
    if (!WriteProcessMemory(hProcess, pRemoteDllPath, fullPath, (wcslen(fullPath) + 1) * sizeof(wchar_t), nullptr)) {
        std::wcerr << L"[-] Failed to write DLL path. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // создаём удалённый поток для загрузки DLL
    hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteDllPath, 0, nullptr);
    if (!hThread) {
        std::wcerr << L"[-] Failed to create remote thread. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::wcout << L"[+] DLL injected successfully." << std::endl;
    return true;
}

// char -> wchar_t
std::wstring AnsiToWide(const char* str) {
    int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    if (len == 0) return L"";

    std::wstring wstr(len - 1, L'\0');
    MultiByteToWideChar(CP_ACP, 0, str, -1, &wstr[0], len);
    return wstr;
}

// получение PID процесса по имени
DWORD GetPIDByName(const WCHAR* processName) {
    DWORD pid = 0;
    HANDLE hProcessSnap;
    PROCESSENTRY32W pe32;

    // создание снимка процессов
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create process snapshot. Error code: " << GetLastError() << std::endl;
        return 0;
    }

    // установка размера структуры PROCESSENTRY32
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // получение информации о первом процессе в снимке
    if (!Process32FirstW(hProcessSnap, &pe32)) {
        std::wcerr << L"Failed to get process information. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcessSnap);
        return 0;
    }
    do {
        if (wcscmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return pid;
}

int main(int argc, char* argv[]) {
	DWORD pid = 0;                                     // PID процесса
	wchar_t dllPath[] = L"hook.dll";                   // Путь к DLL
	LPCTSTR PipeName = TEXT("\\\\.\\pipe\\monitor");   // Имя именованного канала
	HANDLE PipeHandle;                                 // Дескриптор именованного канала
	std::wstring ProcName;                             // Имя процесса
	std::string param1;                                // Параметр -func или -hide
	std::string param2;                                // название функции или путь к файлу
	bool Listening = true;                             // Флаг для общения с DLL
	bool result;                                       // Результат чтения/записи в Pipe
    CHAR MessageBuff[BUFFER_SIZE];	                   // Отправить/получить сообщение к Monitor
    DWORD bytesRead;					               // Сколько байт получено

    if (argc < 3) {
        std::cout << "Usage:\n"
            << "Monitor.exe -pid <PID> -func <functionName>\n"
            << "Monitor.exe -name <processName> -func <functionName>\n"
            << "Monitor.exe -name <processName> -hide <filePath>\n";
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-pid") == 0 && i + 1 < argc) {
            pid = std::stoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-name") == 0 && i + 1 < argc) {
            ProcName = AnsiToWide(argv[i + 1]);
            std::wcout << "[+] Waiting for process \"" << ProcName << "\" to start..." << std::endl;
            while (pid == 0) {
                pid = GetPIDByName(ProcName.c_str());
                if (pid == 0) {
                    Sleep(1000); // 1 секунда  
                }
            }
            std::wcout << "[+] Process \"" << ProcName << "\" found with PID: " << pid << std::endl;
            i++;
        } else if (strcmp(argv[i], "-func") == 0 && i + 1 < argc) {
            param1 = std::string(argv[i]);
            param2 = std::string(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-hide") == 0 && i + 1 < argc) {
            param1 = std::string(argv[i]);
            param2 = std::string(argv[i + 1]);
            i++;
        } else {
            std::cerr << "[-] Error: Invalid arguments!" << std::endl;
            return 1;
        }
    }

    if (pid == 0) {
        std::cerr << "[-] Error: Invalid arguments for PID or process name!" << std::endl;
        return 1;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == nullptr) {
        std::cerr << "[-] Failed to get handle of kernel32.dll. Error code: " << GetLastError() << std::endl;
        return 1;
    }
  
    if (param1 == "-func") {
        if (!GetProcAddress(hKernel32, (LPCSTR)param2.c_str())) {
            std::cerr << "[-] Error: Function not found in kernel32.dll!" << std::endl;
            return 1;
        }
        if (!InjectDLL(pid, dllPath)) {
            std::cerr << "[-] Error: DLL injection failed!" << std::endl;
            return 1;
        }
    } else if (param1 == "-hide") {
        if (GetFileAttributesA((LPCSTR)param2.c_str()) == INVALID_FILE_ATTRIBUTES) {
            std::cerr << "[-] Error: File does not exist!" << std::endl;
            return 1;
        }
        if (!InjectDLL(pid, dllPath)) {
            std::cerr << "[-] Error: DLL injection failed!" << std::endl;
            return 1;
        }
    } else {
        std::cerr << "[-] Error: Invalid arguments!" << std::endl;
        return 1;
    }

	// подключаемся к именованному каналу
    if (ConnectPipe(&PipeHandle, PipeName)) {
        // отправляем параметр "-hide" или "-func"
        WriteToPipe(PipeHandle, param1.c_str());
        while (Listening) {
            // получаем ответ от DLL в MessageBuff
            result = ReadFromPipe(PipeHandle, MessageBuff, BUFFER_SIZE, &bytesRead);
            if (!result || bytesRead == 0) {
                if (GetLastError() == ERROR_BROKEN_PIPE) {
                    printf("[*] Client disconnected.\n");
                    break;
                } else {
                    printf("[-] ReadFilePipe %d\n", GetLastError());
                    return 1;
                }
            }
            // если ответ от DLL ок - продолжаем
            if (strstr(MessageBuff, "OK")) {
                printf("[+] DLL: %s\n", MessageBuff);

                // если func - отправляем название функции
                // если hide - отправляем путь к файлу
                result = WriteToPipe(PipeHandle, param2.c_str());
                if (!result) {
                    if (GetLastError() == ERROR_BROKEN_PIPE) {
                        printf("[*] Client disconnected.\n");
                        break;
                    } else {
                        printf("[-] WriteFile pipe %d\n", GetLastError());
                        return 1;
                    }
                }
                result = ReadFromPipe(PipeHandle, MessageBuff, BUFFER_SIZE, &bytesRead);
                if (!result || bytesRead == 0) {
                    if (GetLastError() == ERROR_BROKEN_PIPE) {
                        printf("[*] Client disconnected.\n");
                        break;
                    } else {
                        printf("[-] ReadFilePipe %d\n", GetLastError());
                        return 1;
                    }
                }
                if (strstr(MessageBuff, "OK")) {
                    printf("[+] DLL: %s\n", MessageBuff);
					// если -hide, то прекращаем общение с DLL
                    if (param1 == "-hide") {
                        Listening = false;
                    }
                } else {
                    printf("[-] Error: %s\n", MessageBuff);
                }
            } else {
                printf("[*] DLL Message: %s\n", MessageBuff);
            }
        }
        DisconnectNamedPipe(PipeHandle);
        CloseHandle(PipeHandle);
    }
    return 0;
}