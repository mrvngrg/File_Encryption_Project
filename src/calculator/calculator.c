#include <stdbool.h>
#include <stdio.h>
void *start_calculator(void *arg) {
    double num1, num2;
    char operator;
 
    while (true) {
        printf("Enter: number operator number\n> ");
 
        if (scanf("%lf %c %lf", &num1, &operator, &num2) != 3) {
            while (getchar() != '\n');
            printf("Invalid input. Use format: 3 + 5\n");
            continue;
        }
 
        switch (operator) {
            case '+':
                printf("= %.6g\n\n", num1 + num2);
                break;
            case '-':
                printf("= %.6g\n\n", num1 - num2);
                break;
            case '*':
                printf("= %.6g\n\n", num1 * num2);
                break;
            case '/':
                if (num2 == 0) {
                    printf("Error: division by zero\n\n");
                } else {
                    printf("= %.6g\n\n", num1 / num2);
                }
                break;
            default:
                printf("Unknown operator '%c'. Use +, -, *, /\n\n", operator);
                break;
        }
    }
 
    return NULL;
}