#pragma once

bool IsDseEnabledNtdll();
bool IsVbsEnabled();
bool IsHvciEnabled();
void SystemChecks();
void ManageProblematicServices();
void RestoreProblematicServices();
void ManageProblematicTasks();
