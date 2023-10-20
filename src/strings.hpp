#pragma once

#include <cstdint>
#include <string>

#include <ankerl/unordered_dense.h>

struct string_data_source_t
{
    void* body;
    const char*(*fptr)(void*);

    template<class T>
    string_data_source_t(T& t)
        : body(&t)
        , fptr([](void* p) -> const char* { return static_cast<T*>(p)->data(); })
    {}

    const char* data() const noexcept
    {
        return fptr(body);
    }
};

struct string_slice_t
{
    string_data_source_t* source = nullptr;
    uint32_t offset = 0;
    uint32_t length = 0;

    std::string_view view() const noexcept
    {
        return std::string_view(source->data() + offset, length);
    }

    bool operator==(const string_slice_t& other) const noexcept
    {
        return view() == other.view();
    }
};

template<>
struct ankerl::unordered_dense::hash<string_slice_t>
{
    using is_avalanching = void;
    uint64_t operator()(const string_slice_t& key) const noexcept
    {
        auto sv = key.view();
        return detail::wyhash::hash(sv.data(), sv.size());
    }
};

inline
bool fuzzy_char_compare(std::string_view value, size_t& index, const char c)
{
    char n = value[index];
    if (n > 127) {
        index += n < 224 ? 1 : n < 240 ? 2 : 3;
        n = '?';
    } else {
        n = char(std::tolower(n));
    }

    return n == c;
}

inline
bool fuzzy_contains(std::string_view value, std::string_view str)
{
    const size_t value_count = value.length();
    const size_t str_count = str.length();

    if (str_count > value_count)
        return false;
    if (str_count == 0)
        return true;

    const char first = str[0];
    const size_t max = value_count - str_count;

    for (size_t i = 0; i < max; ++i) {
        if (fuzzy_char_compare(value, i, first)) {
            while (++i <= max && !fuzzy_char_compare(value, i, first));
        }

        if (i <= max) {
            size_t j = i + 1;
            const size_t true_end = j + str_count;
            const size_t end = (value_count > true_end) ? true_end : value_count;
            for (size_t k = 0
                ; j < end && fuzzy_char_compare(value, j, str[k])
                ; ++j, ++k);

            if (j == true_end)
                return true;
        }
    }

    return false;
}