#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#define MAXLENGTH 101
DWORD GetProcessID(char*);											// ������� ��������� ID ��������

void main(void)
{
	LPCTSTR pipename = "\\\\.\\pipe\\mynamedpipe";					// ��� ������
	HANDLE hProcessB;												// ���������� �������� B
	LPVOID szAddress;												// ����� � ������ �������� B
	DWORD cbWritten, cbRead, dBuf;									// ������� (����� ������������� ��������)
	BOOL Success;													// ���� ��������� ��������/����������/������
	DWORD szSize = sizeof(char) * MAXLENGTH;						// ������ �������� ������
	char *str = (char*)malloc(szSize);								// ���� ������
	HANDLE hPipe = INVALID_HANDLE_VALUE;							// ���������� ������

	printf("Enter your string: ");
	gets_s(str, MAXLENGTH - 1);

	printf("Opening ProcessB...");
	hProcessB = OpenProcess(
		PROCESS_ALL_ACCESS,											// ������������� ������� ������� � ������� ��������
		FALSE,														// �������� ����������� ������������
		GetProcessID("ProcessB.exe"));	                            // ID �������� (� ������ ������ - �������� B)
	if (hProcessB == INVALID_HANDLE_VALUE) {
		printf("Failure!\n");
		system("pause");
		return -1;
	}

	printf("Success!\nAllocating memory for ProcessB...");
	szAddress = VirtualAllocEx(
		hProcessB,													// ���������� �������� (� ������ ������ - �������� B)
		0,															// ������� ���� ������, ��� �������� ������
		szSize,														// ����� ������������� ������
		MEM_RESERVE |												// ������ ��������������� � �����������
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);									// ������� ������

	printf("Success!\nWriting your string in ProcessB memory...");
	Success = WriteProcessMemory(
		hProcessB,													// ���������� �������� (� ������ ������ - �������� B)
		szAddress,													// ���� ����������
		str,														// ��� ����������
		szSize,														// ����� ������������ ������
		0);															// ��������� �� ����������, ������� �������� ����� ������, ���������� � ��������� ������� (������������)
	if (Success == FALSE) {
		printf("Failure!\n");
		system("pause");
		return -1;
	}

	printf("Success!\nConnecting to named pipe...");
	while (hPipe == INVALID_HANDLE_VALUE) {
		hPipe = CreateFile(
			pipename,												// ��� ������������ ������
			GENERIC_READ |											// ������� ������ � ������ � ������
			GENERIC_WRITE,
			0,														// ��� ����������� ������� 
			NULL,													// ��� ������������ ������
			OPEN_EXISTING,											// ��������� ������������ �����
			0,														// �������� ����� �� ��������� 
			NULL);													// ��� ����������� ����� �������
	}

	printf("Success!\nWriting memory address...");
	dBuf = (DWORD)szAddress;
	Success = WriteFile(
		hPipe,														// ���������� ������ 
		&dBuf,														// ������ ��� ������ (� ������ ������ - ����� ������ � �������� B) 
		sizeof(dBuf),												// ����� ������������ ������
		&cbWritten,													// ���������� ���������� ������ (�� ����������)
		NULL);														// ����������� ����� (�� ����������)
	if (Success == FALSE) {
		printf("Failure!\n");
		system("pause");
		return -1;
	}

	printf("Success!\nWaiting answer from ProcessB...");
	Success = ReadFile(
		hPipe,														// ��� ������������ ������
		&szAddress,													// ����� ��� ����������
		sizeof(szAddress),											// ����� ����������� ������
		&cbRead,													// ���������� ��������� ������ (�� ����������)
		NULL);														// ����������� ����� (�� ����������)
	if (Success == FALSE) {
		printf("Failure!\n");
		system("pause");
		return -1;
	}

	printf("Success!\nReleasing ProcessB memory...");
	Success = VirtualFreeEx(
		hProcessB,
		szAddress,
		0,
		MEM_RELEASE);
	if (Success == FALSE) {
		printf("Failure!\n");
		system("pause");
		return -1;
	}

	printf("Success!\nClosing named pipe...");
	Success = CloseHandle(hPipe);
	if (Success == FALSE) {
		printf("Failure!\n");
		system("pause");
		return -1;
	}

	printf("Success!\nClosing ProcessB...");
	Success = CloseHandle(hProcessB);
	if (Success == FALSE) {
		printf("Failure!!!\n");
		system("pause");
		return -1;
	}

	printf("Success!\nProcessA was finished...\n");
	system("pause");
	//return 0;
}

DWORD GetProcessID(char* process) {
	PROCESSENTRY32 processEntry;
	DWORD processID = 0;
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Snapshot != INVALID_HANDLE_VALUE) {
		processEntry.dwSize = sizeof(processEntry);
		Process32First(Snapshot, &processEntry);

		do {
			if (strcmp(processEntry.szExeFile, process) == 0) {
				processID = processEntry.th32ProcessID;
				break;
			}
		} while (Process32Next(Snapshot, &processEntry));

		CloseHandle(Snapshot);
	}

	return processID;
}