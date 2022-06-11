package haw.aydosch.Blatt3.Aufg1;

public class NumberHelper {
    public static boolean checkIfPrime(int n) {
        int i,m=0,flag=0;
        m=n/2;
        if(n==0||n==1){
           return false;
        }else{
            for(i=2;i<=m;i++){
                if(n%i==0){
                    return false;
                }
            }

            return true;
        }
    }
}
