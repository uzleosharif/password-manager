
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
#include <expected>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

// TODO: possibly make everything noexcept for faster code

// TODO: concept for PasswordsMap template type
// TODO: protected access to PasswordsMap

namespace {

std::string_view constexpr kPasswordFilePath{"/tmp/passwords.json"};

enum class UserEvent { kAdd, kKill, kNone };

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
template <class PasswordsMap>
auto LoadPasswords() -> std::expected<PasswordsMap, std::string> {
  // NOTE: This might seem to be a unnecessary check but this routine is meant to be called rarely (e.g. at start of program) so this check can still be kept as
  // it will not have an performance impact.
  if (not std::filesystem::exists(kPasswordFilePath)) {
    std::ofstream password_f{kPasswordFilePath};
    if (not password_f.is_open()) {
      return std::unexpected{"Could not create an empty passwords file on specified path."};
    }

    password_f << R"({"foo": "bar"})" << '\n';
  }

  nlohmann::json password_j{};
  std::ifstream password_f{kPasswordFilePath};
  try {
    password_f >> password_j;
  } catch (std::exception const& e) {
    return std::unexpected{std::format("Passwords file seems corrupted as couldn't parse into json format. Exception: {}", e.what())};
  }

  PasswordsMap passwords_map{};
  std::ranges::transform(password_j.items(), std::inserter(passwords_map, std::end(passwords_map)),
                         [](auto const& entry) { return std::make_pair(entry.key(), entry.value()); });
  return passwords_map;
}

auto WelcomeScreen() {
  std::println("Welcome to Password Manager!!");
  std::println("a : add password entry");
  std::println("x : close app");
  std::println("S : show all managed passwords");
  std::println("");
}

template <CommunicationChannelConcept CommunicationChannel, class PasswordsMap>
auto UserInputTask(std::shared_ptr<CommunicationChannel> communication_channel, std::shared_ptr<PasswordsMap> passwords_map) {
  using namespace std::literals;

  std::string input{};
  bool keep_going{true};

  std::unordered_map<std::string_view, std::function<void()>> const kActionMap{
      {"x"sv,
       [&communication_channel, &keep_going]() {
         communication_channel->Push(Message{.user_event = UserEvent::kKill});
         keep_going = false;
       }},
      {"a"sv, [&communication_channel]() { communication_channel->Push(Message{.user_event = UserEvent::kAdd}); }},
      {"S"sv, [&passwords_map]() {
         std::println("Currently, I am managing following passwords:");
         for (auto const& [k, v] : *passwords_map) {
           std::println("{} -> {}", k, v);
         }
       }}};

  while (keep_going) {
    std::getline(std::cin, input);

    try {
      kActionMap.at(input)();
    } catch (std::exception const& ex) {
      std::println("The passed input is not supported yet. Please try again!");
      std::println("");
    }
  }
}

// TODO: why not pass shared_ptr as template type -> possibly because the concept applies to resource type and not shared_ptr!!
template <CommunicationChannelConcept CommunicationChannel, class PasswordsMap>
auto UserEventHandler(std::shared_ptr<CommunicationChannel> communication_channel, std::shared_ptr<PasswordsMap> passwords_map) {
  using namespace std::chrono_literals;

  bool keep_going{true};

  std::unordered_map<UserEvent, std::function<void()>> const kActionMap{{UserEvent::kKill, [&keep_going]() { keep_going = false; }},
                                                                        {UserEvent::kAdd, []() {
                                                                           std::print("username: ");
                                                                           std::string username{};
                                                                           std::getline(std::cin, username);

                                                                           std::print("password: ");
                                                                           std::string password{};
                                                                           std::getline(std::cin, password);
                                                                         }}};

  while (keep_going) {
    // TODO: use condition-variable instead for more precise timing control
    std::this_thread::sleep_for(10ms);

    while (not communication_channel->Empty()) {
      auto message{communication_channel->Pop()};

      try {
        kActionMap.at(message.user_event)();
      } catch (std::exception const& ex) {
        spdlog::error("No action associated with {} user-event.", static_cast<int>(message.user_event));
      }
    }
  }
}

auto SavePasswords() {
  // TODO: save passwords
}

template <CommunicationChannelConcept CommunicationChannel, class PasswordsMap>
auto LaunchTasks() {
  auto expected_passwords_map{LoadPasswords<PasswordsMap>()};
  if (not expected_passwords_map.has_value()) {
    spdlog::error(expected_passwords_map.error());
    return;
  }

  auto passwords_map{std::make_shared<PasswordsMap>(expected_passwords_map.value())};

  // set up the communication channel meant for inter-thread communication
  auto communication_channel{std::make_shared<CommunicationChannel>()};

  // set up async tasks:
  // - one handling user input
  // - one reacting to user events

  auto ui_fut{std::async(std::launch::async, UserInputTask<CommunicationChannel, PasswordsMap>, communication_channel, passwords_map)};
  auto eh_fut{std::async(UserEventHandler<CommunicationChannel, PasswordsMap>, communication_channel, passwords_map)};

  ui_fut.wait();
  eh_fut.wait();

  SavePasswords();
}

}  // namespace

auto main() -> int {
  WelcomeScreen();
  LaunchTasks<MessageQueue, std::unordered_map<std::string, std::string>>();
}
