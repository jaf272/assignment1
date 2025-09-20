import java.util.*;

public final class IntrusionChainFinder {

  /**
   * Perform a recursive backtracking search to find all valid chains from start to target.
   * A chain stops immediately upon first reaching target.
   *
   * @param scenario the scenario containing all systems and exploits
   * @param start    the system where the attacker begins
   * @param target   the system the attacker is trying to reach
   * @param maxHops  maximum number of hops allowed in a chain
   * @return a list of valid chains (each chain is a list of Hop objects)
   */
  public static List<List<Hop>> findChains(
      ScenarioFactory.Scenario scenario,
      SystemInfo start,
      SystemInfo target,
      int maxHops) {

    // TODO: implement recursive backtracking search using a helper recursive method

    


    return new ArrayList<>();
  }

    // need to implement all helper methods

  // helper method to get priviledge level in ordernal manner
  private static int priviledge_order(Priv p){
    if(p == Priv.ADMIN){
      return 2;
    }
    else if(p == Priv.USER){
      return 1;
    }
    else{
      return 0;
    }
  }

  private static boolean sufficient_priviledge(Priv have, Priv need){
    int have_numeric = priviledge_order(have);
    int need_numeric = priviledge_order(need);
    
    // no priviledge needed case
    if(need == null){
      return true;
    }

    if(have_numeric >= need_numeric){
      return true;
    }
    else{
      return false;
    }
  }


}
