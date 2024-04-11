
// SPDX-License-Identifier: MIT

// Objective
// -----------
// {account -> password} stored as encrypted blob on disk

// Features to do:
// [x] kill application (x)
// [ ] show passwords (s)
// [ ] add password (a)
// [ ] delete password (d)
// [ ] encryption of passwords before writing to disk

// NOTE:
// For inter-thread communication, there are generally 2 possibilities:
// - Message passing
//   - Producer thread generates the message and passes it over to consumer thread
// - Message queue
//   - Prodcuer keeps generating events and pushing to the queue while consumer keeps working on them
//
// Due to non-blocking nature of message-queue mechanism, we have opted to go for message-queue strategy.

#include <fstream>
#include <string_view>
#include <print>
#include <future>
#include <iostream>
#include <queue>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

// TODO: possibly make everything noexcept for faster code

namespace {

std::string_view constexpr kPasswordFilePath{"/tmp/passwords.json"};

enum class UserEvent { kKill, kNone };

template <class Element>
class ThreadSafeQueue final {
 public:
  auto Push(Element&& element) {
    std::lock_guard<std::mutex> lock{m_mutex};
    m_queue.push(std::forward<Element>(element));
  }

  auto Pop() {
    std::lock_guard<std::mutex> lock{m_mutex};
    auto element{m_queue.front()};
    m_queue.pop();
    return element;
  }

  auto Empty() {
    std::lock_guard<std::mutex> lock{m_mutex};
    return m_queue.empty();
  }

  auto Print() { std::println("this is thread-safe-queue"); }

 private:
  std::queue<Element> m_queue{};
  std::mutex m_mutex{};
};

struct Message {
  UserEvent user_event{UserEvent::kNone};
};

using MessageQueue = ThreadSafeQueue<Message>;

template <class CommunicationChannel>
concept CommunicationChannelConcept = requires(CommunicationChannel channel, Message&& message) {
  { channel.Push(std::move(message)) } -> std::same_as<void>;
  { channel.Pop() } -> std::same_as<Message>;
  { channel.Empty() } -> std::same_as<bool>;
};

/// Loads current stored passwords from disk to memory for faster in-app access
auto LoadPasswords() {
  // NOTE: This might seem to be a unnecessary check but this routine is meant to be called rarely (e.g. at start of program) so this check can still be kept as
  // it will not have an performance impact.
  if (not std::filesystem::exists(kPasswordFilePath)) {
    std::ofstream password_f{kPasswordFilePath};
    if (not password_f.is_open()) {
      spdlog::error("Could not create an empty passwords file on specified path.");
      return;
    }

    password_f << R"({"foo": "bar"})" << '\n';
  }

  nlohmann::json password_j{};
  std::ifstream password_f{kPasswordFilePath};
  try {
    password_f >> password_j;
  } catch (std::exception const& e) {
    spdlog::error("Passwords file seems corrupted as couldn't parse into json format. Exception: {}", e.what());
    return;
  }
}

auto WelcomeScreen() {
  std::println("Welcome to Password Manager!!");
  std::println("x : close app");
  std::println("");
}

template <CommunicationChannelConcept CommunicationChannel>
auto UserInputTask(std::shared_ptr<CommunicationChannel> communication_channel_arg) {
  auto communication_channel{communication_channel_arg};

  while (true) {
    std::string input{};
    std::getline(std::cin, input);

    if (input == "x") {
      communication_channel->Push(Message{.user_event = UserEvent::kKill});
      break;
    }
  }
}

template <CommunicationChannelConcept CommunicationChannel>
auto UserEventHandler(std::shared_ptr<CommunicationChannel> communication_channel_arg) {
  using namespace std::chrono_literals;

  auto communication_channel{communication_channel_arg};

  bool keep_going{true};
  while (keep_going) {
    // TODO: use condition-variable instead for more precise timing control
    std::this_thread::sleep_for(10ms);

    while (not communication_channel->Empty()) {
      auto message{communication_channel->Pop()};
      switch (message.user_event) {
        case UserEvent::kKill: {
          keep_going = false;
          break;
        }
        case UserEvent::kNone: {
          spdlog::error("Queue got corrupted somehow as it got a kNone user-event.");
          break;
        }
      }
    }
  }
}

auto Initialize() {
  WelcomeScreen();
  LoadPasswords();
}

template <CommunicationChannelConcept CommunicationChannel>
auto LaunchTasks() {
  // set up the communication channel meant for inter-thread communication
  auto communication_channel{std::make_shared<CommunicationChannel>()};

  // set up async tasks:
  // - one handling user input
  // - one reacting to user events

  auto ui_fut{std::async(std::launch::async, UserInputTask<CommunicationChannel>, communication_channel)};
  ui_fut.wait();

  auto eh_fut{std::async(std::launch::async, UserEventHandler<CommunicationChannel>, communication_channel)};
  eh_fut.wait();
}

auto Cleanup() {
  // TODO: save passwords
}

}  // namespace

auto main() -> int {
  // get app into a valid start up state
  Initialize();

  LaunchTasks<MessageQueue>();

  Cleanup();
}
