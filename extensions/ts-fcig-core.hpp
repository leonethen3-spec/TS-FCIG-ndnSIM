#ifndef TS_FCIG_CORE_HPP
#define TS_FCIG_CORE_HPP

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <deque>
#include <limits>
#include <utility>

namespace tsfcig {

// Detection parameters are independent of the traffic generator's attack period.
constexpr double SampleSeconds = 0.05;
constexpr unsigned ArrivalWindowSamples = 240; // 12 seconds
constexpr unsigned MinimumLag = 20;           // 1 second
constexpr unsigned MaximumLag = 120;          // 6 seconds, inclusive
constexpr unsigned MinimumPairs = 10;
constexpr double PeakProminence = 0.15;
constexpr unsigned StableEstimates = 3;
constexpr unsigned MaximumLagDeviation = 4;   // 0.2 seconds
constexpr double PetWindowSeconds = 1.0;
constexpr double PetBaselineSeconds = 0.1;
constexpr double Threshold = 0.8;
constexpr double BlacklistSeconds = 60.0;

enum class DecisionMode { Complete, PetOnly, AcfOnly };

struct PeriodEstimate
{
  unsigned lag = 0;
  double strength = 0.0;
  bool ready = false;
};

// Pearson correlation of the two overlapping segments (paper Eq. 1).
inline double Correlation(const std::deque<double>& values, unsigned lag)
{
  if (lag == 0 || values.size() <= lag) return 0.0;
  const size_t count = values.size() - lag;
  double aMean = 0.0, bMean = 0.0;
  for (size_t i = 0; i < count; ++i) {
    aMean += values[i];
    bMean += values[i + lag];
  }
  aMean /= count;
  bMean /= count;
  double numerator = 0.0, aEnergy = 0.0, bEnergy = 0.0;
  for (size_t i = 0; i < count; ++i) {
    const double a = values[i] - aMean, b = values[i + lag] - bMean;
    numerator += a * b;
    aEnergy += a * a;
    bEnergy += b * b;
  }
  if (aEnergy == 0.0 || bEnergy == 0.0) return 0.0;
  return std::max(-1.0, std::min(1.0, numerator / std::sqrt(aEnergy * bEnergy)));
}

// Algorithm 1: support lags may extend outside the candidate interval.
inline PeriodEstimate EstimatePeriod(const std::deque<double>& values,
                                     unsigned& previousLag, unsigned& stableCount)
{
  // A candidate at lag 120 needs its right shoulder at lag 150.
  std::array<double, 151> correlations{};
  std::array<bool, 151> available{};
  for (unsigned h = 1; h <= 150; ++h) {
    if (values.size() >= h + MinimumPairs) {
      available[h] = true;
      correlations[h] = Correlation(values, h);
    }
  }
  unsigned selected = 0;
  double strongest = -std::numeric_limits<double>::infinity();
  for (unsigned k = MinimumLag; k <= MaximumLag; ++k) {
    const unsigned d = std::max(2u, k / 4);
    if (!available[k] || !available[k - 1] || !available[k + 1] ||
        !available[k - d] || !available[k + d]) continue;
    const double value = correlations[k];
    const double left = correlations[k - 1], right = correlations[k + 1];
    const double prominence = value - std::max(correlations[k - d], correlations[k + d]);
    if (value >= left && value >= right && (value > left || value > right) &&
        prominence >= PeakProminence && value > strongest) {
      selected = k;
      strongest = value; // Ascending iteration selects the smallest lag on a tie.
    }
  }
  if (selected == 0) {
    stableCount = 0;
    return PeriodEstimate{};
  }
  const unsigned deviation = selected > previousLag ? selected - previousLag : previousLag - selected;
  stableCount = deviation <= MaximumLagDeviation ? stableCount + 1 : 1;
  previousLag = selected;
  PeriodEstimate result;
  result.ready = stableCount >= StableEstimates;
  if (result.ready) {
    result.lag = selected;
    result.strength = std::max(0.0, strongest);
  }
  return result;
}

// Algorithm 2: only completed PIT entries contribute; an empty queue is unavailable.
struct PetWindow
{
  std::deque<std::pair<double, double>> events; // completion time, initial-admission lifetime
  double lifetimeSum = 0.0;

  void Add(double completionTime, double lifetime)
  {
    events.emplace_back(completionTime, lifetime);
    lifetimeSum += lifetime;
  }

  void Prune(double now)
  {
    while (!events.empty() && events.front().first < now - PetWindowSeconds) {
      lifetimeSum -= events.front().second;
      events.pop_front();
    }
    if (events.empty()) lifetimeSum = 0.0;
  }

  bool Valid() const { return !events.empty(); }
  double Mean() const { return Valid() ? lifetimeSum / events.size() : 0.0; }
  double Anomaly() const
  {
    const double mean = Mean();
    return std::max(mean - PetBaselineSeconds, 0.0) / (mean + PetBaselineSeconds);
  }
};

// Eq. 5: left shoulder, trapezoid, right shoulder on the normalized domain.
inline std::array<double, 3> Membership(double x)
{
  x = std::max(0.0, std::min(1.0, x));
  const double low = x <= 0.2 ? 1.0 : x < 0.4 ? 2.0 - 5.0 * x : 0.0;
  const double medium = x > 0.2 && x < 0.4 ? 5.0 * x - 1.0 :
                        x >= 0.4 && x <= 0.6 ? 1.0 :
                        x > 0.6 && x < 0.8 ? 4.0 - 5.0 * x : 0.0;
  const double high = x <= 0.6 ? 0.0 : x < 0.8 ? 5.0 * x - 3.0 : 1.0;
  return {{low, medium, high}};
}

// Table 2 and Eqs. 6-7: min activation and zero-order Sugeno singleton average.
inline double FuzzyState(double acf, double pet)
{
  const auto a = Membership(acf), p = Membership(pet);
  const double weights[3][3] = {{0.0, 0.0, 0.5}, {0.0, 0.5, 0.5}, {0.5, 0.5, 1.0}};
  double numerator = 0.0, denominator = 0.0;
  for (unsigned i = 0; i < 3; ++i) {
    for (unsigned j = 0; j < 3; ++j) {
      const double activation = std::min(a[i], p[j]);
      numerator += activation * weights[i][j];
      denominator += activation;
    }
  }
  return denominator > 0.0 ? numerator / denominator : 0.0;
}

// Eq. 8 resets evidence on every invalid or below-reference update.
inline bool Accumulate(double fuzzy, bool valid, double& accumulator)
{
  accumulator = valid && fuzzy > Threshold ? accumulator + fuzzy - Threshold : 0.0;
  // Four 0.2 increments must reach 0.8 despite binary floating-point roundoff.
  return valid && accumulator + 1e-12 >= Threshold;
}

} // namespace tsfcig
#endif
