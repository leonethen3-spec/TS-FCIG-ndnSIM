#include "collusive-producer.hpp"

#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/ndnSIM/helper/ndn-fib-helper.hpp"
#include "ns3/ndnSIM/helper/ndn-stack-helper.hpp"

NS_LOG_COMPONENT_DEFINE("CollusiveProducer");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED(CollusiveProducer);

TypeId
CollusiveProducer::GetTypeId()
{
  static TypeId tid =
    TypeId("ns3::CollusiveProducer")
      .SetParent<ndn::App>()
      .SetGroupName("Ndn")
      .AddConstructor<CollusiveProducer>()
      .AddAttribute("Prefix", "Prefix served by the collusive producer",
                    StringValue("/root/evil1"),
                    ndn::MakeNameAccessor(&CollusiveProducer::m_prefix),
                    ndn::MakeNameChecker())
      .AddAttribute("ResponseDelay", "Intentional delay before returning Data",
                    TimeValue(Seconds(1.6)),
                    MakeTimeAccessor(&CollusiveProducer::m_responseDelay),
                    MakeTimeChecker())
      .AddAttribute("PayloadSize", "Data payload size in bytes",
                    UintegerValue(1024),
                    MakeUintegerAccessor(&CollusiveProducer::m_payloadSize),
                    MakeUintegerChecker<uint32_t>());
  return tid;
}

CollusiveProducer::CollusiveProducer() = default;
CollusiveProducer::~CollusiveProducer() = default;

void
CollusiveProducer::StartApplication()
{
  ndn::App::StartApplication();
  ndn::FibHelper::AddRoute(GetNode(), m_prefix, m_face, 0);
}

void
CollusiveProducer::StopApplication()
{
  ndn::App::StopApplication();
}

void
CollusiveProducer::OnInterest(std::shared_ptr<const ndn::Interest> interest)
{
  ndn::App::OnInterest(interest);
  if (!m_active || !m_prefix.isPrefixOf(interest->getName())) {
    return;
  }

  NS_LOG_INFO("Scheduling delayed Data for " << interest->getName()
                                              << " after " << m_responseDelay.GetSeconds() << " s");
  Simulator::Schedule(m_responseDelay, &CollusiveProducer::SendData, this, interest,
                      Simulator::Now());
}

void
CollusiveProducer::SendData(std::shared_ptr<const ndn::Interest> interest, Time receivedAt)
{
  if (!m_active) {
    return;
  }

  auto data = std::make_shared<ndn::Data>(interest->getName());
  data->setFreshnessPeriod(ndn::time::milliseconds(0));
  data->setContent(std::make_shared<::ndn::Buffer>(m_payloadSize));
  ndn::StackHelper::getKeyChain().sign(*data);
  m_transmittedDatas(data, this, m_face);
  m_appLink->onReceiveData(*data);
  NS_LOG_INFO("Sent delayed Data for " << interest->getName()
                                        << " at " << Simulator::Now().GetSeconds()
                                        << " after actual delay "
                                        << (Simulator::Now() - receivedAt).GetSeconds() << " s");
}

} // namespace ns3
