#include "Attack.hpp"
#include "Data.hpp"
#include "Keys.hpp"
#include "Progress.hpp"
#include "Zreduction.hpp"

#include <climits>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace {
std::string error;
std::ostringstream output;
std::unique_ptr<Data> data;
std::unique_ptr<Zreduction> reduction;
std::unique_ptr<Progress> progress;
std::unique_ptr<Attack> workerAttack;
std::vector<Keys> solutions;
std::mutex solutionsMutex;
std::size_t cursor = 0;

void clearState()
{
    workerAttack.reset();
    progress.reset();
    reduction.reset();
    data.reset();
    solutions.clear();
    cursor = 0;
    output.str("");
    output.clear();
    error.clear();
}
} // namespace

extern "C" {

const char* bk_error()
{
    return error.c_str();
}

void bk_reset()
{
    clearState();
}

int bk_prepare(const std::uint8_t* cipher, int cipherSize, const std::uint8_t* plain, int plainSize, int plainOffset)
{
    clearState();
    if (cipherSize < 0 || plainSize < 0 || (cipherSize > 0 && cipher == nullptr) || (plainSize > 0 && plain == nullptr))
    {
        error = "invalid recovery input";
        return -1;
    }
    try
    {
        data = std::make_unique<Data>(std::vector<std::uint8_t>{cipher, cipher + cipherSize},
                                     std::vector<std::uint8_t>{plain, plain + plainSize}, plainOffset,
                                     std::map<int, std::uint8_t>{});
        progress = std::make_unique<Progress>(output);
        reduction = std::make_unique<Zreduction>(data->keystream);
        if (data->keystream.size() > Attack::contiguousSize)
            reduction->reduce(*progress);
        reduction->generate();
        if (reduction->getCandidates().size() > INT_MAX)
        {
            clearState();
            error = "too many reduced states";
            return -1;
        }
        workerAttack = std::make_unique<Attack>(*data, reduction->getIndex(), solutions, solutionsMutex, false, *progress);
        return static_cast<int>(reduction->getCandidates().size());
    }
    catch (const std::exception& exception)
    {
        error = exception.what();
        return -1;
    }
}

int bk_step(int count)
{
    if (count <= 0)
    {
        error = "step count must be positive";
        return -1;
    }
    if (!workerAttack || !reduction)
    {
        error = "recovery has not been prepared";
        return -1;
    }
    const auto& candidates = reduction->getCandidates();
    const auto end = std::min(candidates.size(), cursor + static_cast<std::size_t>(count));
    try
    {
        while (cursor < end && solutions.empty())
            workerAttack->carryout(candidates[cursor++]);
    }
    catch (const std::exception& exception)
    {
        error = exception.what();
        return -1;
    }
    if (!solutions.empty())
        return 1;
    return cursor == candidates.size() ? 0 : 2;
}

int bk_cursor()
{
    return static_cast<int>(cursor);
}

std::uint32_t bk_key_x()
{
    return solutions.empty() ? 0 : solutions.front().getX();
}

std::uint32_t bk_key_y()
{
    return solutions.empty() ? 0 : solutions.front().getY();
}

std::uint32_t bk_key_z()
{
    return solutions.empty() ? 0 : solutions.front().getZ();
}

int bk_self_test()
{
    clearState();
    const auto cipher = std::vector<std::uint8_t>{
        0x3e, 0xb4, 0xc5, 0x92, 0x58, 0x40, 0x9a, 0x6c, 0xed, 0x99, 0x65, 0x81,
        0x66, 0x1b, 0x1d, 0xda, 0x5d, 0x8a, 0x8c, 0x30, 0x07, 0x76, 0x50, 0xbb,
    };
    const auto plain = std::vector<std::uint8_t>{'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    try
    {
        auto testData = Data{cipher, plain, 0, {}};
        auto testProgress = Progress{output};
        auto testSolutions = std::vector<Keys>{};
        auto testMutex = std::mutex{};
        auto testAttack = Attack{testData, 7, testSolutions, testMutex, false, testProgress};
        testAttack.carryout(0x74930e64);
        return testSolutions.size() == 1 && testSolutions[0].getX() == 0xea9b4e4d &&
                       testSolutions[0].getY() == 0xba789085 && testSolutions[0].getZ() == 0x5ff8707d
                   ? 1
                   : 0;
    }
    catch (const std::exception& exception)
    {
        error = exception.what();
        return 0;
    }
}
}