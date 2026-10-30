#include <iostream>

struct ICheck {
    virtual ~ICheck() = default;
    virtual void apply() = 0;
    virtual void title() = 0;
};

struct BaseCheck : ICheck {
    void title() override {
        std::cout << "BaseCheck::title" << std::endl;
    }
};

struct FileCheck : BaseCheck {
    void apply() override {
        std::cout << "FileCheck::apply" << std::endl;
    }

    void title() override {
        std::cout << "FileCheck::title" << std::endl;
    }
};

struct SecretCheck : BaseCheck {
    void apply() override {
        std::cout << "SecretCheck::apply" << std::endl;
    }

    void title() override {
        std::cout << "SecretCheck::title" << std::endl;
    }
};

int main() {
    FileCheck file;
    ICheck* check = &file;
    std::cout << "до подмены" << std::endl;
    check->title();
    check->apply();
    std::cout << "пауза для отладчика" << std::endl;
    check->title();
    std::cout << "вызов apply после подмены слота" << std::endl;
    check->apply();
    return 0;
}
