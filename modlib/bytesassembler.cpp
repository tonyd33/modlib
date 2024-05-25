#include <vector>
#include "modlib.h"

namespace Util
{
    BytesAssembler& BytesAssembler::operator<<(uint8_t byte)
    {
        bytes.push_back(byte);
        return *this;
    }

    BytesAssembler& BytesAssembler::operator<<(const std::string& data)
    {
        bytes.insert(bytes.end(), data.begin(), data.end());
        return *this;
    }

    BytesAssembler& BytesAssembler::operator<<(const std::vector<unsigned char>& data)
    {
        bytes.insert(bytes.end(), data.begin(), data.end());
        return *this;
    }

    BytesAssembler& BytesAssembler::operator<<(uint32_t value)
    {
        std::vector<char> toPush =
        {
            static_cast<char>(value & 0xFF),
            static_cast<char>((value >> 8) & 0xFF),
            static_cast<char>((value >> 16) & 0xFF),
            static_cast<char>((value >> 24) & 0xFF),
        };
        if constexpr (std::endian::native != std::endian::little)
            std::reverse(toPush.begin(), toPush.end());
        bytes.insert(std::end(bytes), std::begin(toPush), std::end(toPush));
        return *this;
    }

    BytesAssembler& BytesAssembler::operator<<(uint64_t value)
    {

        std::vector<char> toPush =
        {
            static_cast<char>(value & 0xFF),
            static_cast<char>((value >> 8) & 0xFF),
            static_cast<char>((value >> 16) & 0xFF),
            static_cast<char>((value >> 24) & 0xFF),
            static_cast<char>((value >> 32) & 0xFF),
            static_cast<char>((value >> 40) & 0xFF),
            static_cast<char>((value >> 48) & 0xFF),
            static_cast<char>((value >> 56) & 0xFF),
        };
        if constexpr (std::endian::native != std::endian::little)
            std::reverse(toPush.begin(), toPush.end());
        bytes.insert(std::end(bytes), std::begin(toPush), std::end(toPush));
        return *this;
    }

    size_t BytesAssembler::size() const
    {
        return bytes.size();
    }

    const char* BytesAssembler::data() const
    {
        return bytes.data();
    }

}