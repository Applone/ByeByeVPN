#pragma once

#include <string>
#include <string_view>

#include "../analysis/verdict.h"

// Run full VPN detection analysis on a target
[[nodiscard]] FullReport run_full_target(std::string_view target);
