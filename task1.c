#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>

#define NUM_WORKERS 3
#define SIGNALS_PER_WORKER 2
const int WORKER_SIGNALS_LIST[] = {SIGUSR1, SIGUSR2};
#define NUM_DEFINED_SIGNALS (sizeof(WORKER_SIGNALS_LIST) / sizeof(WORKER_SIGNALS_LIST[0]))

typedef struct {
    struct timespec timestamp;
    int signal_num;
    pid_t sender_pid;
} SignalEvent;

typedef struct {
    int signal_num;
    pid_t sender_pid;
} PipeMessage;

int self_pipe_fd[2];
SignalEvent *signal_events_log = NULL;
size_t events_count = 0;
size_t events_capacity = 0;
volatile sig_atomic_t terminate_controller_flag = 0;

// Обробник сигналів
static void generic_signal_handler(int signum, siginfo_t *siginfo, void *context) {
    (void)context;
    PipeMessage msg;
    msg.signal_num = signum;
    msg.sender_pid = siginfo->si_pid;
    ssize_t written_bytes = write(self_pipe_fd[1], &msg, sizeof(PipeMessage));
}

// Обробник SIGINT
static void sigint_handler(int signum) {
    (void)signum;
    char msg[] = "\nКОНТРОЛЕР: Отримано SIGINT, починаю завершення...\n";
    write(STDOUT_FILENO, msg, sizeof(msg) -1);
    terminate_controller_flag = 1;
    char dummy = '$'; 
    write(self_pipe_fd[1], &dummy, 1);
}

// Функції для роботи з масивом подій
void add_signal_event(int signal_num, pid_t sender_pid) {
    if (events_count >= events_capacity) {
        events_capacity = (events_capacity == 0) ? 16 : events_capacity * 2;
        SignalEvent *new_log = realloc(signal_events_log, events_capacity * sizeof(SignalEvent));
        if (!new_log) {
            perror("Неможливо розширити пам'ять для журналу подій");
            terminate_controller_flag = 1;
            return;
        }
        signal_events_log = new_log;
    }
    clock_gettime(CLOCK_REALTIME, &signal_events_log[events_count].timestamp);
    signal_events_log[events_count].signal_num = signal_num;
    signal_events_log[events_count].sender_pid = sender_pid;
    events_count++;
}

int compare_signal_events(const void *a, const void *b) {
    const SignalEvent *event_a = (const SignalEvent *)a;
    const SignalEvent *event_b = (const SignalEvent *)b;
    if (event_a->timestamp.tv_sec < event_b->timestamp.tv_sec) {
        return -1;
    }
    if (event_a->timestamp.tv_sec > event_b->timestamp.tv_sec) {
        return 1;
    }
    if (event_a->timestamp.tv_nsec < event_b->timestamp.tv_nsec) {
        return -1;
    }
    if (event_a->timestamp.tv_nsec > event_b->timestamp.tv_nsec) {
        return 1;
    }
    return 0;
}

// Логіка процесу-робітника
void worker_task(int worker_id, pid_t controller_pid) {
    srand(time(NULL) ^ getpid());
    printf("  РОБІТНИК %d (PID %d): Стартував, надсилатиму сигнали контролеру (PID %d).\n", worker_id, getpid(), controller_pid);
    for (int i = 0; i < SIGNALS_PER_WORKER; i++) {
        usleep((rand() % 800 + 200) * 1000);
        int signal_to_send = WORKER_SIGNALS_LIST[i % NUM_DEFINED_SIGNALS];
        printf("  РОБІТНИК %d (PID %d): Надсилаю сигнал %s (%d) контролеру.\n", worker_id, getpid(), strsignal(signal_to_send), signal_to_send);

        if (kill(controller_pid, signal_to_send) == -1) {
            perror("  РОБІТНИК: помилка kill");
        }
    }
    printf("  РОБІТНИК %d (PID %d): Всі сигнали надіслано. Завершую роботу.\n", worker_id, getpid());
    exit(worker_id);
}

// Функція для обчислення різниці часу timespec
struct timespec timespec_diff(struct timespec start, struct timespec end) {
    struct timespec temp;
    if ((end.tv_nsec - start.tv_nsec) < 0) {
        temp.tv_sec = end.tv_sec - start.tv_sec - 1;
        temp.tv_nsec = 1000000000L + end.tv_nsec - start.tv_nsec;
    }
    else {
        temp.tv_sec = end.tv_sec - start.tv_sec;
        temp.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
    return temp;
}

// Функція порівняння для сортування PID 
int compare_pids_for_sort(const void *a, const void *b) {
    pid_t pid_a = *(const pid_t *)a;
    pid_t pid_b = *(const pid_t *)b;
    if (pid_a < pid_b) {
        return -1;
    }
    if (pid_a > pid_b) {
        return 1;
    }
    return 0;
}

// Оновлена функція для відображення часової лінії
void print_timeline_pseudographic() {
    if (events_count == 0) {
        printf("Жодного сигналу не було зареєстровано.\n");
        return;
    }

    pid_t unique_sender_pids[NUM_WORKERS * SIGNALS_PER_WORKER];
    int num_unique_senders = 0;
    for (size_t i = 0; i < events_count; i++) {
        int found = 0;
        for (int j = 0; j < num_unique_senders; j++) {
            if (signal_events_log[i].sender_pid == unique_sender_pids[j]) {
                found = 1;
                break;
            }
        }
        if (!found) {
            if (num_unique_senders < (int)(sizeof(unique_sender_pids)/sizeof(pid_t))) {
                 unique_sender_pids[num_unique_senders++] = signal_events_log[i].sender_pid;
            }
        }
    }

    if (num_unique_senders > 0) {
        qsort(unique_sender_pids, num_unique_senders, sizeof(pid_t), compare_pids_for_sort);
    }

    printf("\n--- Часова Лінія Отриманих Сигналів ---\n");
    int abs_time_width = 21;
    int rel_time_width = 14;
    int pid_col_width = 26;

    printf("%-*s | %-*s |", abs_time_width, "Абсолютний час", rel_time_width, "Відносний час");
    for (int i = 0; i < num_unique_senders; i++) {
        char pid_header[30];
        snprintf(pid_header, sizeof(pid_header), "Робітник (PID %d)", unique_sender_pids[i]);
        printf(" %-*s |", pid_col_width, pid_header);
    }
    printf("\n");

    for (int i = 0; i < abs_time_width; i++) {
        printf("-");
    }
    printf(" | ");
    for (int i = 0; i < rel_time_width; i++) {
        printf("-");
    }
    printf(" |");
    for (int i = 0; i < num_unique_senders; i++) {
        printf(" ");
        for (int k = 0; k < pid_col_width; k++) {
            printf("-");
        }
        printf(" |");
    }
    printf("\n");

    struct timespec prev_ts = signal_events_log[0].timestamp;

    for (size_t i = 0; i < events_count; i++) {
        char abs_time_buf[abs_time_width + 1];
        char rel_time_buf[rel_time_width + 1];
        struct timespec current_ts = signal_events_log[i].timestamp;
        struct timespec diff_ts;

        snprintf(abs_time_buf, sizeof(abs_time_buf), "%ld.%09ld", current_ts.tv_sec, current_ts.tv_nsec);

        if (i == 0) {
            diff_ts.tv_sec = 0;
            diff_ts.tv_nsec = 0;
        }
        else {
            diff_ts = timespec_diff(prev_ts, current_ts);
        }

        snprintf(rel_time_buf, sizeof(rel_time_buf), "+%ld.%09lds", diff_ts.tv_sec, diff_ts.tv_nsec);
        
        printf("%-*s | %-*s |", abs_time_width, abs_time_buf, rel_time_width, rel_time_buf);

        for (int j = 0; j < num_unique_senders; j++) {
            if (signal_events_log[i].sender_pid == unique_sender_pids[j]) {
                char signal_info[pid_col_width + 1];
                const char* sig_name = strsignal(signal_events_log[i].signal_num);
                if (sig_name == NULL) {
                    sig_name = "UNKNOWN";
                }
                snprintf(signal_info, sizeof(signal_info), "%s (%d)", sig_name, signal_events_log[i].signal_num);
                printf(" %-*s |", pid_col_width, signal_info);
            } 
            else {
                printf(" %-*s |", pid_col_width, "");
            }
        }
        printf("\n");
        prev_ts = current_ts;
    }
    printf("---------------------------------------------------------------------------------------------------\n");
}

// Основна логіка контролера
int main() {
    pid_t worker_pids[NUM_WORKERS];
    int active_workers_count = 0;
    struct sigaction sa_app, sa_int;

    printf("КОНТРОЛЕР (PID: %d): Старт програми.\n", getpid());

    if (pipe(self_pipe_fd) == -1) {
        perror("Неможливо створити self-pipe");
        exit(EXIT_FAILURE);
    }
    if (fcntl(self_pipe_fd[0], F_SETFL, O_NONBLOCK) == -1 ||
        fcntl(self_pipe_fd[1], F_SETFL, O_NONBLOCK) == -1) {
        perror("Неможливо встановити неблокуючий режим для pipe");
        close(self_pipe_fd[0]);
        close(self_pipe_fd[1]);
        exit(EXIT_FAILURE);
    }

    sa_app.sa_sigaction = generic_signal_handler;
    sigemptyset(&sa_app.sa_mask);
    sa_app.sa_flags = SA_SIGINFO | SA_RESTART;
    for (size_t i = 0; i < NUM_DEFINED_SIGNALS; i++) {
        if (sigaction(WORKER_SIGNALS_LIST[i], &sa_app, NULL) == -1) {
            perror("Неможливо встановити обробник сигналу програми");
            exit(EXIT_FAILURE);
        }
    }

    sa_int.sa_handler = sigint_handler;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = SA_RESTART;
    
    if (sigaction(SIGINT, &sa_int, NULL) == -1) { 
        perror("Неможливо встановити обробник SIGINT");
        exit(EXIT_FAILURE);
    }

    printf("КОНТРОЛЕР: Створюю %d робітників...\n", NUM_WORKERS);
    for (int i = 0; i < NUM_WORKERS; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("Помилка fork");
            for (int j = 0; j < i; j++) {
                if(worker_pids[j]>0) {
                    kill(worker_pids[j], SIGTERM);
                }
            }
            while(wait(NULL) > 0);
            exit(EXIT_FAILURE);
        }
        else if (pid == 0) {
            close(self_pipe_fd[0]);
            worker_task(i + 1, getppid());
        }
        else {
            worker_pids[i] = pid;
            active_workers_count++;
        }
    }
    printf("КОНТРОЛЕР: Всі робітники створені. Очікую на сигнали...\n");

    fd_set read_fds;
    PipeMessage msg_from_pipe;
    int expected_total_signals = NUM_WORKERS * SIGNALS_PER_WORKER;

    while ((active_workers_count > 0 || events_count < (size_t)expected_total_signals) && !terminate_controller_flag) {
        FD_ZERO(&read_fds);
        FD_SET(self_pipe_fd[0], &read_fds);
        struct timeval timeout = {1, 0};
        int activity = select(self_pipe_fd[0] + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("Помилка select");
            terminate_controller_flag = 1;
            break;
        }
        if (terminate_controller_flag) {
            break;
        }

        if (FD_ISSET(self_pipe_fd[0], &read_fds)) {
            ssize_t bytes_read;

            while ((bytes_read = read(self_pipe_fd[0], &msg_from_pipe, sizeof(PipeMessage))) > 0) {
                if (msg_from_pipe.signal_num == 0 && msg_from_pipe.sender_pid == 0 && bytes_read == 1 && *((char*)&msg_from_pipe) == '$') {
                    // вже оброблено прапорцем
                }
                else if (bytes_read == sizeof(PipeMessage)) {
                    add_signal_event(msg_from_pipe.signal_num, msg_from_pipe.sender_pid);
                    printf("КОНТРОЛЕР: Зареєстровано сигнал %s (%d) від PID %d.\n", strsignal(msg_from_pipe.signal_num), msg_from_pipe.signal_num, msg_from_pipe.sender_pid);
                }
            }
            if (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("КОНТРОЛЕР: Помилка читання з pipe");
                terminate_controller_flag = 1;
                break;
            }
        }

        pid_t terminated_pid;
        int status;
        while ((terminated_pid = waitpid(-1, &status, WNOHANG)) > 0) {
            printf("КОНТРОЛЕР: Робітник PID %d завершив роботу зі статусом %d.\n", terminated_pid, WEXITSTATUS(status));
            active_workers_count--;
             for(int k=0; k<NUM_WORKERS; k++) {
                 if(worker_pids[k] == terminated_pid) {
                     worker_pids[k] = -1;
                 }
             }
        }
        if (terminated_pid < 0 && errno != ECHILD && errno != EINTR) {
             perror("Помилка waitpid в основному циклі");
             terminate_controller_flag = 1;
             break;
        }
        
        if (active_workers_count == 0 && (events_count >= (size_t)expected_total_signals || terminate_controller_flag) ) {
            if (!terminate_controller_flag) {
                printf("КОНТРОЛЕР: Всі робітники завершились і очікувані сигнали отримано.\n");
            }
            break;
        }
    }

    printf("\nКОНТРОЛЕР: Основний цикл завершено. Оброблено %zu подій.\n", events_count);
    close(self_pipe_fd[0]);
    close(self_pipe_fd[1]);
    
    while(active_workers_count > 0) { // Якщо цикл завершився через terminate_controller_flag, а діти ще є
        pid_t term_pid = wait(NULL);
        if (term_pid > 0) {
            printf("КОНТРОЛЕР: Остаточно зібрано робітника PID %d.\n", term_pid);
            active_workers_count--;
             for(int k=0; k<NUM_WORKERS; k++) {
                 if(worker_pids[k] == term_pid) {
                     worker_pids[k] = -1;
                 }
             }
        }
        else if (errno == ECHILD) {
            active_workers_count = 0;
            break; 
        }
        else if (errno != EINTR) {
            perror("Помилка остаточного wait");
            break;
        }
    }

    if (events_count > 0) {
        qsort(signal_events_log, events_count, sizeof(SignalEvent), compare_signal_events);
    }

    print_timeline_pseudographic();

    free(signal_events_log);
    printf("КОНТРОЛЕР: Завершення роботи.\n");
    return 0;
}
